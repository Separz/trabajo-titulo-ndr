#!/bin/sh
# Firewall del segmento
# enrutamiento, NAT de salida y blocklist con expiracion
# Es idempotente y al reaplicarlo se vacia la blocklist
# Lo invoca config-lab.sh que entrega la ip de la interfaz WAN
set -e

LAN_IP="10.10.10.1/24"
LAN_IFACE="eth1"
WAN_IP="${1:-100.64.0.1/24}"
WAN_IFACE="eth2"

# Asigna una ip a una interfaz solo si aun no la tiene
# El "ip" de busybox no trae "ip addr replace"
asignar_ip() {
  direccion="$1"
  interfaz="$2"
  if ! ip addr show dev "$interfaz" | grep -q "inet $direccion"; then
    ip addr add "$direccion" dev "$interfaz"
  fi
}

apk add --no-cache nftables >/dev/null

# 1. Direcciones
# la LAN queda en el lado interno, antes del NAT
asignar_ip "$LAN_IP" "$LAN_IFACE"
asignar_ip "$WAN_IP" "$WAN_IFACE"

# 2. Permitir que el kernel reenvie paquetes entre interfaces (router)
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 3. Reglas de nftables
# Se usan tablas propias para no tocar las que administra Docker
# Declarar la tabla y borrarla justo despues permite recrearla sin error si ya existia
nft -f - <<NFT
table inet ndr
delete table inet ndr
table inet ndr {
  # ips bloqueadas. Cada elemento puede llevar un timeout y se elimina solo al expirar.
  set blocklist {
    type ipv4_addr
    flags timeout
  }

  chain forward {
    type filter hook forward priority 0; policy accept;
    ip saddr @blocklist counter drop
  }
}

table ip ndr_nat
delete table ip ndr_nat
table ip ndr_nat {
  # NAT de salida: lo que sale por la WAN lleva la ip del firewall
  chain postrouting {
    type nat hook postrouting priority 100;
    oifname "$WAN_IFACE" masquerade
  }
}
NFT

echo "fw listo"
