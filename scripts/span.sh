#!/bin/bash
# Administra la sesion SPAN del switch sw1 en Open vSwitch
# Copia todo el trafico del switch hacia el puerto donde escucha Zeek
# Uso: sudo ./scripts/span.sh [on|off|status]
set -euo pipefail

BRIDGE=sw1
PUERTO_SENSOR=zeek-eth1
MIRROR=span0

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

mirror_existe() {
  ovs-vsctl --bare --columns=name find Mirror name="$MIRROR" | grep -qx "$MIRROR"
}

activar() {
  # Partir de estado limpio
  ovs-vsctl clear Bridge "$BRIDGE" mirrors

  # Tres pasos en una sola transaccion segun manual de ovs-vsctl:
  # - obtener el puerto de salida y guardarlo como @salida
  # - crear el mirror que copia todo el trafico select-all hacia @salida
  # - asociar el mirror al bridge
  ovs-vsctl \
    -- --id=@salida get Port "$PUERTO_SENSOR" \
    -- --id=@sesion create Mirror name="$MIRROR" select-all=true output-port=@salida \
    -- set Bridge "$BRIDGE" mirrors=@sesion >/dev/null

  if ! mirror_existe; then
    fail "el mirror $MIRROR no quedo creado"
  fi
  echo "SPAN activo"
}

desactivar() {
  ovs-vsctl clear Bridge "$BRIDGE" mirrors
  echo "SPAN eliminado"
}

estado() {
  ovs-vsctl list Mirror
}

if [ "$(id -u)" -ne 0 ]; then
  fail "span.sh requiere root (ovs-vsctl). Ejecutar con sudo"
fi

ACCION="${1:-on}"

case "$ACCION" in
  on)     activar ;;
  off)    desactivar ;;
  status) estado ;;
  *)      fail "uso: sudo $0 [on|off|status]" ;;
esac
