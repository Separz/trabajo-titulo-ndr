#!/bin/bash
# Configura el laboratorio despues de "containerlab deploy"
# Uso: sudo ./scripts/config-lab.sh
set -euo pipefail

LAB=clab-ndr-lab

# Red LAN del segmento
LAN_PREFIJO="10.10.10"
LAN_GATEWAY="$LAN_PREFIJO.1"

# Red WAN del enlace fw-inet
# Se usa el rango CGNAT 100.64.0.0/10 ya que Slips no lo trata como red privada
WAN_PREFIJO="100.64.0"
WAN_RED="$WAN_PREFIJO.0/24"
FW_WAN_IP="$WAN_PREFIJO.1"
C2_IP="$WAN_PREFIJO.2"

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

# Ejecuta un comando dentro de un nodo del lab
# Ej: en_nodo pc1 ping -c 1 10.10.10.1
en_nodo() {
  local nodo="$1"
  shift
  docker exec "$LAB-$nodo" "$@"
}

# Asigna la ip de un equipo de la LAN y su ruta hacia la WAN.
# Ej: configurar_equipo pc1 11 -> 10.10.10.11
configurar_equipo() {
  local nodo="$1"
  local ultimo_octeto="$2"
  en_nodo "$nodo" ip addr replace "$LAN_PREFIJO.$ultimo_octeto/24" dev eth1
  en_nodo "$nodo" ip route replace "$WAN_RED" via "$LAN_GATEWAY"
}

zeek_esta_corriendo() {
  en_nodo zeek sh -c 'kill -0 "$(cat /run/zeek.pid)"'
}

span_esta_activo() {
  ovs-vsctl --bare --columns=name find Mirror name=span0 | grep -qx span0
}

verificar() {
  local codigo_http

  echo
  echo "Verificacion:"

  printf "  SPAN       : "
  if span_esta_activo; then echo OK; else echo FALLA; fi

  printf "  pc1 -> fw  : "
  if en_nodo pc1 ping -c 1 -W 2 "$LAN_GATEWAY" >/dev/null; then echo OK; else echo FALLA; fi

  printf "  pc1 -> C2  : "
  if codigo_http=$(en_nodo pc1 curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$C2_IP/"); then
    echo "HTTP $codigo_http"
  else
    echo FALLA
  fi

  echo "  Logs de Zeek: logs/zeek/current/ (esperar aprox 1 min antes de consultarlos)"
}

if [ "$(id -u)" -ne 0 ]; then
  fail "config-lab.sh requiere root (OVS). Ejecutar con: sudo $0"
fi

# Trabajar desde la raiz del repositorio
RAIZ_REPO="$(dirname "$(readlink -f "$0")")/.."
cd "$RAIZ_REPO"

echo "[1/6] Firewall (ips, reenvio, NAT, blocklist)"
en_nodo fw sh /setup.sh "$FW_WAN_IP/24"

echo "[2/6] Direcciones y rutas de los equipos"
en_nodo inet ip addr replace "$C2_IP/24" dev eth1
configurar_equipo pc1 11
configurar_equipo pc2 12

echo "[3/6] Servidor C2 (nginx en inet)"
if ! en_nodo inet pgrep -x nginx >/dev/null; then
  en_nodo inet nginx
fi

echo "[4/6] Sesion SPAN"
./scripts/span.sh on

echo "[5/6] Zeek"
docker exec --detach "$LAB-zeek" bash /start.sh
sleep 3
if ! zeek_esta_corriendo; then
  fail "Zeek no quedo corriendo"
fi

echo "[6/6] Beacon en pc2"
en_nodo pc2 sh /beacon.sh "$C2_IP"

verificar
