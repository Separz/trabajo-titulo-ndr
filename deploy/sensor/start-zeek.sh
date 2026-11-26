#!/bin/bash
# Inicia Zeek sobre el puerto espejo en el sensor fisico.
# Lo ejecuta el contenedor zeek de deploy/sensor/docker-compose.yml.
# - Cada arranque escribe en /logs/run-<fecha> y /logs/current apunta a la ultima
#   corrida para no mezclar datos de corridas distintas.
# - No detiene instancias previas: Docker Compose reinicia el contenedor completo
#   y /run es un tmpfs que queda vacio en cada arranque.
set -euo pipefail

# Interfaz de captura conectada al puerto espejo. Se define en deploy/sensor/.env
IFACE="${IFACE:?definir IFACE en deploy/sensor/.env}"
PIDFILE=/run/zeek.pid
DIR_LOGS=/logs
# Filtro BPF opcional (sintaxis de tcpdump). Vacio: Zeek captura todo
FILTRO_CAPTURA="${FILTRO_CAPTURA:-}"

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

if [ ! -e "/sys/class/net/$IFACE" ]; then
  fail "$IFACE no existe en el sensor (ver: ip -br link)"
fi

# Carpeta propia
CORRIDA="run-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIR_LOGS/$CORRIDA"
ln -sfn "$CORRIDA" "$DIR_LOGS/current"
cd "$DIR_LOGS/$CORRIDA"

# "exec" reemplaza este script por Zeek, que conserva el mismo PID.
# El healthcheck del compose lo usa para saber si Zeek sigue vivo
echo $$ > "$PIDFILE"

# -C -> no descarta paquetes con checksum invalido
# -i -> interfaz de captura
# -f -> filtro BPF; el kernel descarta lo filtrado antes de que llegue a Zeek,
#       que anota el filtro instalado en packet_filter.log
# local -> carga la politica local.zeek que trae la imagen
# LogAscii::use_json=T -> escribe los logs en JSON en vez de TSV
if [ -n "$FILTRO_CAPTURA" ]; then
  exec zeek -C -i "$IFACE" -f "$FILTRO_CAPTURA" local "LogAscii::use_json=T"
fi
exec zeek -C -i "$IFACE" local "LogAscii::use_json=T"
