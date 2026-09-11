#!/bin/bash
# Prepara el host para el laboratorio instalando Open vSwitch y creando el switch sw1
# Se ejecuta una sola vez por host con "sudo ./scripts/host-prep.sh"
set -euo pipefail

OVS_SOCKET=/run/openvswitch/db.sock
BRIDGE=sw1

fail() {
  echo "ERROR: $1" >&2
  exit 1
}

existe_programa() {
  command -v "$1" >/dev/null
}

# Trabajar desde la raiz del repositorio se invoque desde donde se invoque
RAIZ_REPO="$(dirname "$(readlink -f "$0")")/.."
cd "$RAIZ_REPO"

# 1. Instalar Open vSwitch segun la distribucion
if existe_programa pacman; then
  pacman -S --needed --noconfirm openvswitch
elif existe_programa apt-get; then
  apt-get update
  apt-get install -y openvswitch-switch
else
  fail "gestor de paquetes no soportado; instala Open vSwitch manualmente"
fi

# 2. Cargar el modulo de kernel que permite crear el switch virtual
modprobe openvswitch

# 3. Iniciar el servicio segun OS
if systemctl list-unit-files | grep -q '^openvswitch-switch.service'; then
  systemctl enable --now openvswitch-switch.service
else
  systemctl enable --now ovs-vswitchd.service
fi

# 4. Esperar hasta 15 s a que el servicio cree su socket
for _ in $(seq 1 15); do
  if [ -S "$OVS_SOCKET" ]; then
    break
  fi
  sleep 1
done
if [ ! -S "$OVS_SOCKET" ]; then
  fail "$OVS_SOCKET no aparecio en 15 s"
fi

# 5. Crear el switch: debe existir antes de desplegar la topologia
ovs-vsctl --may-exist add-br "$BRIDGE"

# 6. Ajuste que exige el indexer de Wazuh (se pierde al reiniciar el host)
sysctl -w vm.max_map_count=262144

mkdir -p logs/zeek logs/slips
echo "Host listo. Siguiente: sudo containerlab deploy -t ndr-lab.clab.yml"
