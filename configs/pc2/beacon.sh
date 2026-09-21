#!/bin/sh
# Beaconing simulado: una peticion HTTP al "C2" cada 27 a 33 segundos.
# Solo corre una instancia: si ya hay un bucle activo, lo detiene antes de lanzar otro.
# Lo invoca config-lab.sh, que entrega la IP del C2.

C2_IP="${1:-100.64.0.2}"
PIDFILE=/tmp/beacon.pid
INTERVALO_MINIMO=27
VARIACION=7

hay_instancia_previa() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

# Entrega un numero entre 0 y 255 leyendo un byte de /dev/urandom
byte_aleatorio() {
  od -An -N1 -tu1 /dev/urandom
}

emitir_beacons() {
  while true; do
    curl -s -o /dev/null -A "Mozilla/5.0" "http://$C2_IP/"
    espera=$((INTERVALO_MINIMO + $(byte_aleatorio) % VARIACION))
    sleep "$espera"
  done
}

if hay_instancia_previa; then
  kill "$(cat "$PIDFILE")"
fi

emitir_beacons >/dev/null 2>&1 &
echo $! > "$PIDFILE"
