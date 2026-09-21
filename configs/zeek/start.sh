#!/bin/bash
# Inicia Zeek sobre el puerto espejo. Lo invoca config-lab.sh en segundo plano
# - Detiene una instancia previa para evitar dos Zeek escribiendo a la vez
# - Cada ejecucion escribe en /logs/run-<fecha> y /logs/current apunta a la ultima para no mezclar datos de corridas distintas.
set -euo pipefail

# Interfaz de captura. Se puede cambiar con IFACE
# ej: IFACE=enp3s0 en un servidor fisico.
IFACE="${IFACE:-eth1}"
PIDFILE=/run/zeek.pid
DIR_LOGS=/logs

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

hay_instancia_previa() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

if [ ! -e "/sys/class/net/$IFACE" ]; then
  fail "$IFACE no existe; revisar los enlaces de la topologia"
fi

if hay_instancia_previa; then
  kill "$(cat "$PIDFILE")"
  sleep 2
fi

# Carpeta propia
CORRIDA="run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIR_LOGS/$CORRIDA"
ln -sfn "$CORRIDA" "$DIR_LOGS/current"
cd "$DIR_LOGS/$CORRIDA"

# "exec" reemplaza este script por Zeek, que conserva el mismo PID
echo $$ > "$PIDFILE"

# -C -> ignora checksums invalidos (habitual en interfaces virtuales)
# -i -> interfaz de captura
# local -> carga la politica local.zeek que trae la imagen
# LogAscii::use_json=T -> escribe los logs en JSON en vez de TSV
exec zeek -C -i "$IFACE" local "LogAscii::use_json=T"
