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
| Deployment `slips` y ConfigMap del agente | `30-slips.yaml` | Análisis de comportamiento y envío de alertas a Wazuh |
| CronJob `retencion-zeek` | `40-retencion.yaml` | Borra logs con más de 30 días |
| NetworkPolicy | `50-red.yaml` | Limita la salida de red de Slips |

Wazuh no se despliega aquí: ya existe en el clúster y se reactiva en otra tarea. RITA y MISP son complementarios y se incorporan después.

## 2. Decisiones de diseño

### Zeek y Slips en pods separados

| | Mismo pod | Pods separados (elegido) |
|---|---|---|
| Red de Slips | Hereda `hostNetwork` sin necesitarlo | Red de pods normal |
| Privilegios de Slips | Comparte el contexto del sensor | Ninguna capacidad |
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

Zeek y Slips se referencian por digest, el mismo de las imágenes probadas en el laboratorio (Zeek 9.0.0 y Slips 1.1.23). El agente Wazuh usa la etiqueta 4.14.7.

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

Antes del paso 4 hay que reemplazar tres valores:

| Marcador | Archivo | Valor |
|---|---|---|
| `CAMBIAR_INTERFAZ_SPAN` | `20-zeek.yaml` | Nombre de la interfaz física de captura |
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
| 1 | ¿El clúster admite `hostNetwork`, `NET_RAW` y `NET_ADMIN`? ¿Hay un nodo en el segmento con una segunda interfaz? | Consulta al administrador del clúster |
| 2 | Slips deduce la red local desde la interfaz que recibe con `-i`. En el laboratorio tomó la red de gestión y marcó tráfico legítimo con severidad alta; en un pod tomaría la red de pods | Calibración de Slips; revisar cómo fijar la red local |
| 3 | Zeek no rota sus logs en este arranque: un archivo por tipo crece sin límite y la tarea de retención no puede borrar un archivo en uso | Configurar la rotación de logs de Zeek y comprobar que Slips sigue leyendo tras una rotación |
| 4 | El arranque de Slips sin capacidades y sin acceso a Internet no está probado | Prueba en el laboratorio con las mismas restricciones |
| 5 | Registro del agente en el manager: nombre del servicio, puerto 1515 y contraseña de registro si el manager la exige | Depende del acceso administrativo a Wazuh |
| 6 | Sincronización horaria: los contenedores usan el reloj del nodo | Confirmar que los nodos sincronizan por NTP |
| 7 | Control de acceso al namespace `ndr` | Definir con el administrador qué cuentas pueden modificarlo |
