#!/bin/bash
# Prepara un equipo Debian como sensor del NDR:
# - Instala Docker y descarga la imagen de Zeek
# - Ajusta la NIC de captura (GRO, LRO, sin IP)
# - Borra cada noche los logs de Zeek mas antiguos que RETENCION_DIAS
# - Da al host SIEM acceso de solo lectura a los logs para que los traiga con rsync
# Se ejecuta en el sensor, desde el repo clonado, con "sudo ./scripts/sensor-prep.sh"
# Requiere deploy/sensor/.env con IFACE definido (ver deploy/sensor/.env.example)
# Es idempotente y puede repetirse sin duplicar repositorios ni servicios

# -e: termina ante el primer error; -u: error si se usa una variable no definida
# -o pipefail: un pipe falla si falla cualquiera de sus comandos, no solo el ultimo
set -euo pipefail

# Rutas que crea o modifica el script
DOCKER_KEY=/etc/apt/keyrings/docker.asc
DOCKER_SOURCES=/etc/apt/sources.list.d/docker.sources
SERVICIO_NIC=/etc/systemd/system/ndr-nic-captura.service
SERVICIO_RETENCION=/etc/systemd/system/ndr-retencion-zeek.service
TIMER_RETENCION=/etc/systemd/system/ndr-retencion-zeek.timer
INTERFACES=/etc/network/interfaces
INTERFAZ_CAPTURA=/etc/network/interfaces.d/ndr-captura
# Usuario con el que el host SIEM entra por SSH a leer los logs
USUARIO_LOGS=ndr-logs
HOME_LOGS=/var/lib/ndr-logs

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

# Sin deploy/sensor/.env no se sabe que interfaz capturar
[ -f deploy/sensor/.env ] || fail "falta deploy/sensor/.env; copiar deploy/sensor/.env.example y completar IFACE"
# shellcheck source=/dev/null
. deploy/sensor/.env
# IFACE debe estar definida y existir: /sys/class/net lista las interfaces que reconoce el kernel
# Asi un error de tipeo se detecta antes de instalar nada
[ -n "${IFACE:-}" ] || fail "IFACE vacio en deploy/sensor/.env"
[ -e "/sys/class/net/$IFACE" ] || fail "la interfaz $IFACE no existe (ver: ip -br link)"
# Valores por defecto si deploy/sensor/.env no los define
LOGS_DIR="${LOGS_DIR:-/srv/ndr/zeek}"
MGMT_IFACE="${MGMT_IFACE:-}"
RETENCION_DIAS="${RETENCION_DIAS:-30}"
SIEM_PUBKEY="${SIEM_PUBKEY:-deploy/sensor/siem.pub}"
# find -mtime necesita un numero entero de dias
[[ "$RETENCION_DIAS" =~ ^[0-9]+$ ]] || fail "RETENCION_DIAS debe ser un numero de dias: $RETENCION_DIAS"
# Si se definio MGMT_IFACE, verifica que exista y que sea distinta de IFACE
if [ -n "$MGMT_IFACE" ]; then
  [ -e "/sys/class/net/$MGMT_IFACE" ] || fail "la interfaz de gestion $MGMT_IFACE no existe (ver: ip -br link)"
  [ "$MGMT_IFACE" != "$IFACE" ] || fail "MGMT_IFACE debe ser distinta de IFACE"
fi

echo ""
echo "[1/8] Paquetes base"
apt-get update
# openssh-server, rsync y python3: el host SIEM trae los logs por SSH y rrsync, que lo restringe, es un script de python
apt-get install -y ca-certificates curl git ethtool tcpdump chrony rsync python3 openssh-server

# Procedimiento oficial: https://docs.docker.com/engine/install/debian/
echo ""
echo "[2/8] Repositorio de Docker"
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

echo ""
echo "[3/8] Docker Engine y Compose"
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker

# GRO y LRO juntan varios paquetes de una conexion en uno grande antes de entregarlo
# Se desactivan para que Zeek analice los paquetes tal como pasaron por el cable
# ethtool no persiste tras un reinicio ni tras reconectar la NIC
# El servicio queda ligado al dispositivo: se ejecuta cada vez que la interfaz aparece tambien si es USB
# LRO se ignora si falla porque no todas las NIC lo implementan
echo ""
echo "[4/8] NIC de captura ($IFACE): GRO y LRO desactivados cada vez que aparece"
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

echo ""
echo "[5/8] Carpeta de logs e imagen de Zeek"
mkdir -p "$LOGS_DIR"
docker compose -f deploy/sensor/docker-compose.yml pull

# Misma politica que k8s/40-retencion.yaml: cada noche se borran los logs mas antiguos que RETENCION_DIAS
# Un archivo en uso no se borra porque Zeek lo sigue escribiendo y su fecha se actualiza
# Persistent=true ejecuta la limpieza al encender si el equipo estaba apagado a la hora programada
echo ""
echo "[6/8] Retencion de logs de Zeek: $RETENCION_DIAS dias"
cat > "$SERVICIO_RETENCION" <<EOF
[Unit]
Description=Borra los logs de Zeek del NDR con mas de $RETENCION_DIAS dias

[Service]
Type=oneshot
ExecStart=/usr/bin/find $LOGS_DIR -type f -name '*.log*' -mtime +$RETENCION_DIAS -delete
# Carpetas run-<fecha> que quedaron vacias tras la limpieza
ExecStart=/usr/bin/find $LOGS_DIR -mindepth 1 -maxdepth 1 -type d -name 'run-*' -empty -mtime +1 -delete
EOF
cat > "$TIMER_RETENCION" <<EOF
[Unit]
Description=Retencion diaria de los logs de Zeek del NDR

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now ndr-retencion-zeek.timer

# El host SIEM trae los logs con rsync por SSH (pull): el sensor no guarda credenciales del SIEM
# y si se cae la red Zeek sigue escribiendo en el disco local
# La llave del SIEM queda limitada a rrsync en solo lectura sobre LOGS_DIR:
# - restrict: sin terminal, sin reenvio de puertos ni de agente
# - command: cualquier comando que pida el SIEM se reemplaza por rrsync -ro
# El authorized_keys es de root: el usuario puede leerlo pero no modificarlo
echo ""
echo "[7/8] Acceso de solo lectura a los logs para el host SIEM"
if [ ! -s "$SIEM_PUBKEY" ]; then
  echo "  Omitido: falta $SIEM_PUBKEY (llave publica SSH del host SIEM)"
else
  # Valida que el archivo sea una llave publica antes de autorizarla
  ssh-keygen -l -f "$SIEM_PUBKEY" >/dev/null || fail "$SIEM_PUBKEY no es una llave publica SSH valida"
  RRSYNC="$(command -v rrsync)" || fail "no se encontro rrsync (paquete rsync)"
  id -u "$USUARIO_LOGS" >/dev/null 2>&1 || useradd --system --home-dir "$HOME_LOGS" --shell /bin/sh "$USUARIO_LOGS"
  # '*' deja la cuenta sin contrasena pero no bloqueada: solo puede entrar con la llave
  usermod -p '*' "$USUARIO_LOGS"
  install -d -m 0755 -o root -g root "$HOME_LOGS" "$HOME_LOGS/.ssh"
  # Antepone las restricciones a cada llave del archivo, omitiendo lineas vacias
  grep -v '^[[:space:]]*$' "$SIEM_PUBKEY" \
    | sed "s|^|restrict,command=\"$RRSYNC -ro $LOGS_DIR\" |" > "$HOME_LOGS/.ssh/authorized_keys"
  chmod 0644 "$HOME_LOGS/.ssh/authorized_keys"
  echo "  Usuario $USUARIO_LOGS autorizado con $SIEM_PUBKEY"
fi

# Un sensor pasivo no debe tener ip ni enviar trafico por la interfaz de captura
# Sin esto el cliente DHCP del propio sensor aparece en la captura
# Va al final porque puede cortar la red, y solo se aplica si existe otra interfaz
# para administrar el equipo (MGMT_IFACE)
echo ""
echo "[8/8] NIC de captura ($IFACE): sin ip ni DHCP"
# Si no se define MGMT_IFACE, IFACE conserva su configuracion de red
if [ -z "$MGMT_IFACE" ]; then
  echo "  Omitido: MGMT_IFACE no esta definida en deploy/sensor/.env y $IFACE es la unica interfaz de administracion"
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
printf "  Retencion  : %s dias, timer " "$RETENCION_DIAS"; systemctl is-active ndr-retencion-zeek.timer || true
if [ -s "$HOME_LOGS/.ssh/authorized_keys" ]; then
  echo "  Acceso SIEM: $USUARIO_LOGS (rrsync -ro $LOGS_DIR)"
else
  echo "  Acceso SIEM: (sin llave del SIEM)"
fi
echo
echo "Sensor listo. Siguiente: cd deploy/sensor && sudo docker compose up -d"
