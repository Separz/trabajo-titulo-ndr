# TD06 — Diseño del despliegue en Kubernetes

Define cómo se ejecuta el núcleo del NDR (Zeek y Slips) en el clúster del Departamento: recursos, capacidades, restricciones de planificación, almacenamiento persistente y política de reinicio.

Requisitos relacionados: RNF01, RNF02, RNF05, RNF06, RNF08. Depende de las respuestas de TT01. Los manifiestos están en [`k8s/`](../../k8s/) y el diagrama en [`diagramas/despliegue-kubernetes.mmd`](../diagramas/despliegue-kubernetes.mmd).

Estos manifiestos son de diseño: validan contra el esquema de Kubernetes, pero no se han aplicado en un clúster. Los valores marcados `CAMBIAR_...` dependen de datos del clúster institucional.

## 1. Componentes

| Recurso | Archivo | Función |
|---|---|---|
| Namespace `ndr` | `00-namespace.yaml` | Aísla el NDR del resto del clúster |
| StorageClass, 2 PV y 2 PVC | `10-almacenamiento.yaml` | Logs de Zeek y salida de Slips en el disco del nodo de captura |
| Deployment `zeek` | `20-zeek.yaml` | Sensor de captura pasiva |
| Deployment `slips` y ConfigMap del agente | `30-slips.yaml` | Análisis de comportamiento, interfaz de red local de Slips y envío de alertas a Wazuh |
| CronJob `retencion-zeek` | `40-retencion.yaml` | Borra logs con más de 30 días |
| NetworkPolicy | `50-red.yaml` | Limita la salida de red de Slips |

Wazuh no se despliega aquí: ya existe en el clúster y se reactiva en otra tarea. RITA y MISP son complementarios y se incorporan después.

## 2. Decisiones de diseño

### Zeek y Slips en pods separados

| | Mismo pod | Pods separados (elegido) |
|---|---|---|
| Red de Slips | Hereda `hostNetwork` sin necesitarlo | Red de pods normal |
| Privilegios de Slips | Comparte el contexto del sensor | Ninguna capacidad; `NET_ADMIN` solo en un contenedor de inicio (ver «Red local de Slips») |
| NetworkPolicy sobre Slips | No aplica a pods con `hostNetwork` | Aplica |
| Compartir logs | Volumen `emptyDir` del pod | Volumen persistente local, ambos pods en el mismo nodo |
| Reinicio | Reiniciar Slips reinicia la captura | Independiente |

Se eligen pods separados por mínimo privilegio: solo Zeek necesita acceso a la red del nodo. El costo es que ambos pods deben quedar en el mismo nodo, lo que se resuelve con la misma regla de afinidad.

### Captura con `hostNetwork` y afinidad de nodo

El tráfico espejado llega a una interfaz física de un nodo concreto. Por eso el pod de Zeek:

- usa `hostNetwork: true` para ver esa interfaz;
- se fija con `nodeAffinity` al nodo etiquetado `ndr/captura=true`;
- recibe solo dos capacidades, `NET_RAW` (abrir el socket de captura) y `NET_ADMIN` (modo promiscuo), y descarta el resto.

El namespace declara el nivel `privileged` de Pod Security, que es el que admite `hostNetwork`. Queda acotado a este namespace.

Si el clúster no admite `hostNetwork` o no hay un nodo con presencia física en el segmento, la alternativa es un sensor externo al clúster que escriba los logs en un almacenamiento compartido. Esa decisión depende de TT01.

### Red local de Slips

Slips necesita conocer la red local del segmento vigilado. Varias detecciones dependen de ella; la más visible es `DIFFERENT_LOCALNET`, que marca las conexiones hacia direcciones privadas fuera de esa red.

**El problema.** Con `-g`, Slips se considera en ejecución continua y obtiene la red local de la dirección y la máscara de la interfaz que recibe en `-i`. En ese modo ignora la opción `client_ips` de `slips.yaml`, que solo se usa al analizar archivos. Fuentes, en el código de Slips 1.1.23:

- `slips_files/core/helpers/localnet_handler.py`, líneas 115-121 (elección entre interfaz y `client_ips`), 56-82 (cálculo desde la interfaz) y 84-98 (cálculo desde `client_ips`);
- `slips_files/core/database/redis_db/database.py`, líneas 1598-1606 (`is_running_non_stop`, verdadero con `-g`).

La documentación de Slips pide pasar con `-i` «the same interface zeek is running on» (`docs/usage.md`, sección «Growing zeek directories», líneas 221-239). Eso supone un equipo dentro de la red, cuya interfaz de captura tiene una dirección del segmento. No contempla un sensor pasivo en un puerto espejo: en sus 28 documentos no hay referencias a SPAN, espejo ni interfaces sin dirección.

En este diseño ninguna interfaz real sirve:

- `eth0` del pod pertenece a la red del clúster;
- la interfaz de captura es del nodo, la usa Zeek con `hostNetwork`, y no tiene dirección;
- la interfaz de gestión del nodo suele estar en una red de servidores, no en el segmento vigilado.

En el laboratorio ocurría lo mismo: con `-i eth0` Slips tomó la red de gestión (`172.30.30.0/24`) y marcó como externas todas las conexiones del segmento `10.10.10.0/24`.

**La decisión.** Un contenedor de inicio crea en el espacio de red del pod una interfaz virtual de tipo `dummy`, `ndr0`, con una dirección del segmento vigilado, y Slips se lanza con `-i ndr0`. La interfaz no envía ni recibe tráfico: solo le entrega a Slips la dirección de la que deduce la red. El contenedor de inicio recibe únicamente `NET_ADMIN` y termina antes de que arranque Slips, que sigue sin capacidades. La interfaz pertenece al espacio de red del pod, así que sobrevive a los reinicios del contenedor de Slips y se vuelve a crear con el pod.

Es una adaptación propia, no una configuración documentada por Slips. Depende de un detalle interno: si una versión futura cambia cómo se calcula la red local, puede dejar de funcionar. La imagen fijada por digest protege de ese cambio mientras no se actualice.

**Validación.** Se ejecutó Slips 1.1.23 en un contenedor aislado sobre los logs de Zeek del escaneo del 13-10, con `-i ndr0` y la dirección `10.10.10.254/24`. Slips informó `Local Net 10.10.10.0/24 (ndr0)`. El 14-10 se repitió en vivo en el laboratorio, con la 1.1.23 y luego con la 1.1.24 sobre el mismo escaneo, con el mismo resultado en la red local. En la 1.1.24, `localnet_handler.py` es idéntico al de la 1.1.23, así que la interfaz virtual sigue siendo necesaria.

| | Original (`-i eth0`) | Con interfaz virtual (`-i ndr0`) |
|---|---|---|
| Red local deducida | 172.30.30.0/24 | 10.10.10.0/24 |
| Evidencias de conexión fuera de la red local | 4.001 | 0 |
| Evidencias `High` | 2.004 | 3, todas del escaneo real |
| Alertas de Slips | 441 (152 distintas) | 54 (18 distintas) |
| Equipo alertado | `pc2` | `pc2` |

Los comandos del contenedor de inicio se probaron además en un contenedor con solo `NET_ADMIN`, sin otras capacidades: crearon la interfaz, y sin `NET_ADMIN` fallaron con «Operation not permitted». No se han probado en un clúster.

**Alternativas descartadas.**

| Alternativa | Razón |
|---|---|
| Analizar con `-f` (archivos), donde `client_ips` sí se respeta | Es un análisis por lotes. Por la misma razón que RITA (TD04, sección 6), su latencia no es compatible con la respuesta automática. Además cambia el umbral de alerta (0,25 × 3600 / 60 = 15, contra 5 en ejecución continua, `evidence_handler_worker.py`, líneas 95-101) y cada ejecución empieza sin el estado de la anterior |
| Dar `hostNetwork` a Slips | Contradice el mínimo privilegio elegido en esta sección, y la interfaz de captura tampoco tiene dirección |
| Desactivar `DIFFERENT_LOCALNET` en `slips.yaml` | Oculta el síntoma: la red local sigue siendo incorrecta para el resto de las detecciones |
| Pedir al proyecto Slips que respete `client_ips` con `-g` | Es la solución de fondo, pero no depende de este proyecto. Queda como punto abierto |

**Condiciones y efectos conocidos.**

- **La dirección debe estar reservada.** Slips la toma como su propia IP (informó `Host IP 10.10.10.254 (ndr0)`), así que no puede pertenecer a ningún equipo real. En producción debe excluirse del DHCP del segmento.
- **Puerta de enlace.** Con `-i eth0`, Slips informaba la MAC de la puerta de enlace; con `ndr0` no informa ninguna. No se ha evaluado qué detecciones dependen de ella.
- **Una sola red local.** Con `-i`, Slips admite una única red local (`localnet_handler.py`, líneas 100-105) y no distingue VLAN: ningún módulo de detección menciona VLAN. Si el puerto espejo entrega un troncal con varias VLAN:
  - con rangos contiguos, una máscara más amplia en `ndr0` (por ejemplo `/16`) los abarcaría, a costa de tratar como local todo ese bloque; no se ha probado;
  - con rangos no contiguos, no hay solución con esta configuración;
  - si dos VLAN usan el mismo rango, Slips mezclaría equipos distintos en un mismo perfil, porque los perfiles son por dirección IP.
- **Módulo `dummy` del kernel.** El nodo debe permitir crear interfaces de ese tipo. En el laboratorio funcionó; en el nodo de producción hay que confirmarlo.

### Alertas hacia Wazuh mediante un agente

En el laboratorio, el manager lee `alerts.json` desde una carpeta compartida. En el clúster, el manager vive en otro namespace y posiblemente en otro nodo, así que no puede montar el volumen local.

El pod de Slips incluye un segundo contenedor con un agente Wazuh, que lee `alerts.json` y lo envía al manager por el canal cifrado estándar de los agentes (1514/TCP). El agente antepone el prefijo `slips: ` que espera el decodificador de TD04.

Consecuencia: las alertas del NDR aparecen en Wazuh asociadas al agente `ndr-sensor`, no al manager.

### Almacenamiento local

Se usan volúmenes persistentes locales en el nodo de captura, con política `Retain`: los datos sobreviven al reinicio o la reprogramación de los pods y no se borran al eliminar el PVC.

| Volumen | Contenido | Tamaño provisional |
|---|---|---|
| `zeek-logs` | Logs de Zeek en JSON | 100 Gi |
| `slips-output` | Alertas, base SQLite y volcado de Redis de Slips | 20 Gi |

La configuración crítica no vive en volúmenes sino en este repositorio: `slips.yaml` y el script de arranque de Zeek se cargan como ConfigMap, y el decodificador y las reglas de Wazuh están en `docs/diseno/td04/`.

### Restricción de salida de Slips

Varios módulos de Slips consultan servicios externos de inteligencia de amenazas, lo que enviaría direcciones IP de la red universitaria a terceros. La NetworkPolicy permite a Slips únicamente DNS interno y la comunicación del agente con el manager.

El efecto es que esos módulos quedan sin conexión. Deben además deshabilitarse en `slips.yaml` para que no generen errores; esa lista de módulos está pendiente.

### Política de reinicio

Los dos Deployment usan una réplica y estrategia `Recreate`, para que nunca haya dos instancias escribiendo en el mismo volumen. Kubernetes reinicia los contenedores que fallan. Zeek tiene además una sonda que comprueba que el proceso sigue vivo.

### Versiones fijadas

Zeek y Slips se referencian por digest, el mismo de las imágenes probadas en el laboratorio (Zeek 9.0.0 y Slips 1.1.24). Slips pasó de la 1.1.23 a la 1.1.24 el 14-10, porque esta corrige las alertas duplicadas (TD04, sección 5). El agente Wazuh usa la etiqueta 4.14.7.

## 3. Recursos

| Contenedor | CPU solicitada | CPU límite | Memoria solicitada | Memoria límite |
|---|---|---|---|---|
| zeek | 1 | 4 | 2 Gi | 8 Gi |
| slips | 1 | 4 | 2 Gi | 8 Gi |
| wazuh-agent | 0,1 | 0,5 | 128 Mi | 512 Mi |

Son valores provisionales. Zeek se dimensiona según el volumen de tráfico del segmento, que no se conoce todavía; se ajustan tras medir el tráfico real del puerto SPAN.

## 4. Aplicación

```bash
# 1. Marcar el nodo conectado al puerto SPAN
kubectl label node <nodo> ndr/captura=true

# 2. Crear las carpetas del almacenamiento local en ese nodo
sudo mkdir -p /var/lib/ndr/zeek /var/lib/ndr/slips

# 3. Namespace y configuracion tomada del repositorio
kubectl apply -f k8s/00-namespace.yaml
kubectl -n ndr create configmap zeek-scripts --from-file=start.sh=configs/zeek/start.sh
kubectl -n ndr create configmap slips-config --from-file=slips.yaml=configs/slips/slips.yaml

# 4. Resto de los recursos
kubectl apply -f k8s/
```

Antes del paso 4 hay que reemplazar cuatro valores:

| Marcador | Archivo | Valor |
|---|---|---|
| `CAMBIAR_INTERFAZ_SPAN` | `20-zeek.yaml` | Nombre de la interfaz física de captura |
| `CAMBIAR_IP_RED_LOCAL` | `30-slips.yaml` | Dirección reservada del segmento vigilado, con su máscara (por ejemplo `10.10.10.254/24`) |
| `CAMBIAR_SERVICIO_WAZUH_MANAGER` | `30-slips.yaml` (dos veces) | Nombre DNS del servicio del manager |
| `CAMBIAR_NAMESPACE_WAZUH` | `50-red.yaml` | Namespace donde corre Wazuh |

En el manager de Wazuh deben cargarse además el decodificador y las reglas de `docs/diseno/td04/`.

## 5. Validación

Los 11 recursos validan contra el esquema de Kubernetes con `kubeconform` en modo estricto:

```bash
docker run --rm -v "$PWD/k8s:/k:ro" ghcr.io/yannh/kubeconform:latest -strict -summary /k
# Summary: 11 resources found in 6 files - Valid: 11, Invalid: 0, Errors: 0, Skipped: 0
```

Eso comprueba la estructura de los manifiestos, no su funcionamiento.

## 6. Puntos abiertos

| # | Punto | Cómo se resuelve |
|---|---|---|
| 1 | ¿El clúster admite `hostNetwork`, `NET_RAW` y `NET_ADMIN` (este último también en el contenedor de inicio de Slips)? ¿Hay un nodo en el segmento con una segunda interfaz? | Consulta al administrador del clúster |
| 2 | Red local de Slips: resuelta en el diseño con la interfaz virtual (sección 2). Falta saber qué entrega el puerto espejo: ¿una VLAN o un troncal con varias? ¿Qué rangos usa cada una, son contiguos y alguno se repite? | Consulta al administrador de la red |
| 2a | Dirección reservada para `ndr0`, excluida del DHCP del segmento | Consulta al administrador de la red |
| 2b | El nodo de captura permite crear interfaces `dummy` | Prueba en el nodo |
| 2c | Que Slips respete `client_ips` con `-g` eliminaría la interfaz virtual | Abrir un issue en el repositorio de Slips; revisar si la 1.1.24 cambió la detección de la red local |
| 3 | Zeek no rota sus logs en este arranque: un archivo por tipo crece sin límite y la tarea de retención no puede borrar un archivo en uso | Configurar la rotación de logs de Zeek y comprobar que Slips sigue leyendo tras una rotación |
| 4 | El arranque de Slips sin capacidades y sin acceso a Internet no está probado | Prueba en el laboratorio con las mismas restricciones |
| 5 | Registro del agente en el manager: nombre del servicio, puerto 1515 y contraseña de registro si el manager la exige | Depende del acceso administrativo a Wazuh |
| 6 | Sincronización horaria: los contenedores usan el reloj del nodo | Confirmar que los nodos sincronizan por NTP |
| 7 | Control de acceso al namespace `ndr` | Definir con el administrador qué cuentas pueden modificarlo |
| 8 | Resuelto el 14-10. Slips 1.1.23 escribía la misma alerta dos o tres veces; la 1.1.24 lo corrige y se adoptó (TD04, sección 5) | Digest actualizado en `ndr-lab.clab.yml` y `30-slips.yaml`; formato de `alerts.json` y decodificador revalidados en vivo |
| 9 | `alpine:3.20`, usada por la tarea de retención, es una etiqueta de versión menor y no un digest. La rama 3.20 podría haber terminado su período de soporte | Verificar el soporte en el sitio de Alpine y fijarla por digest o pasar a una rama vigente |
