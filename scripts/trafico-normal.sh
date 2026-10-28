#!/bin/sh
# Trafico normal simulado para medir falsos positivos
# Imita a un usuario mediante rafagas de 1 a 6 peticiones HTTP a distintos servidores
# separadas por pausas irregulares de 5 a 124 segundos (sin periodo fijo, a diferencia del beacon)
# Solo corre una instancia, si ya hay un bucle activo lo detiene antes de lanzar otro
# Ejecutar mediante: sh /trafico-normal.sh 100.64.0.10 100.64.0.11 ...

PIDFILE=/tmp/trafico-normal.pid # Archivo para guardar el PID del proceso activo
PAUSA_MINIMA=5 # Pausa mínima entre ráfagas de peticiones
PAUSA_VARIACION=120 # Variación aleatoria de la pausa entre ráfagas (0 a 120 segundos)
MAX_PETICIONES=6 # Número máximo de peticiones por ráfaga

# Validación de argumentos definidos
if [ "$#" -eq 0 ]; then
  echo "ERROR: Debe indicar al menos un servidor" >&2
  exit 1
fi

# Función para verificar si ya hay una instancia previa corriendo
hay_instancia_previa() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

# Entrega random entre 0 y 255
byte_aleatorio() {
  od -An -N1 -tu1 /dev/urandom
}

# Elige uno de los servidores definidos al azar
# Ej: elegir_servidor a b c -> b
elegir_servidor() {
  indice=$(( $(byte_aleatorio) % $# + 1 ))
  eval echo "\${$indice}"
}

# Función principal que simula la navegación web
navegar() {
  while true; do
    servidor=$(elegir_servidor "$@")
    peticiones=$(( $(byte_aleatorio) % MAX_PETICIONES + 1 ))
    for _ in $(seq "$peticiones"); do
      curl -s -o /dev/null -A "Mozilla/5.0 (X11; Linux x86_64)" "http://$servidor/"
      sleep $(( $(byte_aleatorio) % 3 ))
    done
    sleep $(( PAUSA_MINIMA + $(byte_aleatorio) % PAUSA_VARIACION ))
  done
}

# Verifica si hay una instancia previa corriendo y la detiene antes de iniciar una nueva
if hay_instancia_previa; then
  kill "$(cat "$PIDFILE")"
fi

# Inicia la función de navegación en segundo plano y guarda su PID
navegar "$@" >/dev/null 2>&1 &
echo $! > "$PIDFILE"
