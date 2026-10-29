#!/bin/bash
# Prepara un equipo Debian como sensor del NDR:
# - Instala Docker y descarga la imagen de Zeek
# - Ajusta la NIC de captura (GRO, LRO, sin IP)
# Se ejecuta en el sensor, desde el repo clonado, con "sudo ./scripts/sensor-prep.sh"
# Requiere deploy/.env con IFACE definido (ver deploy/.env.example)
# Es idempotente y puede repetirse sin duplicar repositorios ni servicios

# -e: termina ante el primer error; -u: error si se usa una variable no definida
# -o pipefail: un pipe falla si falla cualquiera de sus comandos, no solo el ultimo
set -euo pipefail

# Rutas que crea o modifica el script
DOCKER_KEY=/etc/apt/keyrings/docker.asc
DOCKER_SOURCES=/etc/apt/sources.list.d/docker.sources
SERVICIO_NIC=/etc/systemd/system/ndr-nic-captura.service
INTERFACES=/etc/network/interfaces
INTERFAZ_CAPTURA=/etc/network/interfaces.d/ndr-captura

echo "Este script prepara un equipo Debian como sensor del NDR (Zeek)"
echo "Está seguro de querer continuar (S/n)? (Ctrl+C para cancelar)"
if [ -t 0 ]; then
  read -r respuesta
  if [[ "$respuesta" =~ ^[Nn]$ ]]; then
    echo "Cancelado por el usuario"
    exit 1
  fi
fi


# Imprime el error en stderr y termina con codigo 1 para que el script no continue
fail() {
  echo "ERROR: $1" >&2
  exit 1
}

# Verifica que el script se ejecute como root para poder instalar paquetes y crear servicios
if [ "$(id -u)" -ne 0 ]; then
  fail "sensor-prep.sh requiere root. Ejecutar con: sudo $0"
fi

# Trabajar desde la raiz del repositorio se invoque desde donde se invoque
RAIZ_REPO="$(dirname "$(readlink -f "$0")")/.."
cd "$RAIZ_REPO"

# shellcheck source=/dev/null
. /etc/os-release
# Solo Debian: usa apt, el repositorio de Docker para Debian y la red de ifupdown (/etc/network/interfaces)
if [ "${ID:-}" != "debian" ]; then
  fail "este script es para Debian; el sistema es ${PRETTY_NAME:-desconocido}"
fi

# Sin deploy/.env no se sabe que interfaz capturar
[ -f deploy/.env ] || fail "falta deploy/.env; copiar deploy/.env.example y completar IFACE"
# shellcheck source=/dev/null
. deploy/.env
# IFACE debe estar definida y existir: /sys/class/net lista las interfaces que reconoce el kernel
# Asi un error de tipeo se detecta antes de instalar nada
[ -n "${IFACE:-}" ] || fail "IFACE vacio en deploy/.env"
[ -e "/sys/class/net/$IFACE" ] || fail "la interfaz $IFACE no existe (ver: ip -br link)"
# Valores por defecto si deploy/.env no los define
LOGS_DIR="${LOGS_DIR:-/srv/ndr/zeek}"
MGMT_IFACE="${MGMT_IFACE:-}"
# Si se definio MGMT_IFACE, verifica que exista y que sea distinta de IFACE
if [ -n "$MGMT_IFACE" ]; then
  [ -e "/sys/class/net/$MGMT_IFACE" ] || fail "la interfaz de gestion $MGMT_IFACE no existe (ver: ip -br link)"
  [ "$MGMT_IFACE" != "$IFACE" ] || fail "MGMT_IFACE debe ser distinta de IFACE"
fi

echo "[1/6] Paquetes base"
apt-get update
apt-get install -y ca-certificates curl git ethtool tcpdump chrony

# Procedimiento oficial: https://docs.docker.com/engine/install/debian/
echo "[2/6] Repositorio de Docker"
install -m 0755 -d /etc/apt/keyrings
# Descarga la llave de Docker solo si no existe o esta vacia
if [ ! -s "$DOCKER_KEY" ]; then
  curl -fsSL https://download.docker.com/linux/debian/gpg -o "$DOCKER_KEY"
  chmod a+r "$DOCKER_KEY"
fi
# El archivo del repositorio se reescribe completo: repetir el script no lo duplica
cat > "$DOCKER_SOURCES" <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: $VERSION_CODENAME
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: $DOCKER_KEY
EOF

echo "[3/6] Docker Engine y Compose"
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# GRO y LRO juntan varios paquetes de una conexion en uno grande antes de entregarlo
# Se desactivan para que Zeek analice los paquetes tal como pasaron por el cable
# ethtool no persiste tras un reinicio ni tras reconectar la NIC
# El servicio queda ligado al dispositivo: se ejecuta cada vez que la interfaz aparece tambien si es USB
# LRO se ignora si falla porque no todas las NIC lo implementan
echo "[4/6] NIC de captura ($IFACE): GRO y LRO desactivados cada vez que aparece"
DISPOSITIVO_NIC="sys-subsystem-net-devices-$IFACE.device"
cat > "$SERVICIO_NIC" <<EOF
[Unit]
Description=Ajustes de la NIC de captura del NDR ($IFACE)
BindsTo=$DISPOSITIVO_NIC
After=$DISPOSITIVO_NIC
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ethtool -K $IFACE gro off
ExecStart=-/usr/sbin/ethtool -K $IFACE lro off

[Install]
WantedBy=$DISPOSITIVO_NIC
EOF
systemctl daemon-reload
# reenable borra los enlaces de una ejecucion anterior (otra NIC u otro destino) antes de crearlos
systemctl reenable ndr-nic-captura.service
systemctl restart ndr-nic-captura.service

echo "[5/6] Carpeta de logs e imagen de Zeek"
mkdir -p "$LOGS_DIR"
docker compose -f deploy/docker-compose.yml pull

# Un sensor pasivo no debe tener ip ni enviar trafico por la interfaz de captura
# Sin esto el cliente DHCP del propio sensor aparece en la captura
# Va al final porque puede cortar la red, y solo se aplica si existe otra interfaz
# para administrar el equipo (MGMT_IFACE)
echo "[6/6] NIC de captura ($IFACE): sin ip ni DHCP"
# Si no se define MGMT_IFACE, IFACE conserva su configuracion de red
if [ -z "$MGMT_IFACE" ]; then
  echo "  Omitido: MGMT_IFACE no esta definida en deploy/.env y $IFACE es la unica interfaz de administracion"
else
  # Respaldo unico de la configuracion original del instalador
  [ -f "$INTERFACES.ndr.bak" ] || cp "$INTERFACES" "$INTERFACES.ndr.bak"

  # Comenta las lineas de IFACE en el archivo principal para que no la configure dos veces
  # La estrofa termina en la siguiente linea que empieza otra definicion o en una linea vacia
  awk -v nic="$IFACE" '
    $1 ~ /^(auto|allow-hotplug|allow-auto)$/ && $2 == nic { print "# ndr: " $0; next }
    $1 == "iface" && $2 == nic { en_estrofa = 1; print "# ndr: " $0; next }
    en_estrofa && ($0 ~ /^[[:space:]]*$/ || $1 ~ /^(iface|auto|allow-|source|mapping)/) { en_estrofa = 0 }
    en_estrofa { print "# ndr: " $0; next }
    { print }
  ' "$INTERFACES.ndr.bak" > "$INTERFACES"

  # Agrega la linea de source al final del archivo principal si no existe
  grep -q '^source /etc/network/interfaces.d/\*' "$INTERFACES" || echo "source /etc/network/interfaces.d/*" >> "$INTERFACES"

  # Crea la configuracion de la interfaz de captura; el texto entre EOF se escribe tal cual en el archivo
  # \$IFACE queda literal: ifupdown la reemplaza por el nombre de la interfaz al ejecutar up y down
  mkdir -p /etc/network/interfaces.d
  cat > "$INTERFAZ_CAPTURA" <<EOF
# Interfaz de captura del NDR: sin direccion, levantada y en modo promiscuo
# allow-hotplug la levanta cuando aparece, tambien si es un adaptador USB que se reconecta
allow-hotplug $IFACE
iface $IFACE inet manual
    up ip link set \$IFACE up promisc on
    down ip link set \$IFACE promisc off down
EOF
  echo "  Configurado en $INTERFAZ_CAPTURA (respaldo en $INTERFACES.ndr.bak)"
  echo "  Se aplica al reiniciar el equipo"
fi

echo
echo "Verificacion:"
printf "  Docker     : "; docker --version
printf "  Compose    : "; docker compose version --short
printf "  GRO        : "; ethtool -k "$IFACE" | awk '/generic-receive-offload/ {print $2}'
printf "  LRO        : "; ethtool -k "$IFACE" | awk '/large-receive-offload/ {print $2}'
echo "  Captura    : $IFACE"
echo "  Gestion    : ${MGMT_IFACE:-(no definida)}"
echo "  Logs       : $LOGS_DIR"
echo
echo "Sensor listo. Siguiente: cd deploy && sudo docker compose up -d"
