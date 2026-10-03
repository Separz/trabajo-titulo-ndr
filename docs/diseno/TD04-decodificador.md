# TD04 — Especificación del decodificador de alertas

Define cómo las detecciones de Slips y de RITA se convierten en eventos de Wazuh: qué campos se extraen, a qué campos de Wazuh se asignan y qué nivel de severidad recibe cada una.

Requisitos relacionados: RF05, RF11, RNF09. Insumo para TD05 y para la implementación TT05a, TT05b y TT10.

Referencia principal: García, S. et al. (2026). *Slips: Behavioral Evidence Aggregation for Network Security*. arXiv:2608.11979.

## 1. Entrada: alerta de Slips

Slips 1.1.23 escribe un registro por línea en `alerts.json`, en formato IDMEFv2 (versión `2.D.V03`). Hay dos tipos de registro, que se distinguen por el campo `Status` (García et al., 2026):

- **`Event`: evidencia.** La interpretación que hace un módulo de detección de una o más conexiones. Una evidencia aislada no es una decisión.
- **`Incident`: alerta.** Slips suma la evidencia de cada host dentro de una ventana de tiempo, ponderando nivel de amenaza por confianza; cuando la suma supera el umbral configurado, emite una alerta sobre ese host.

Ejemplo real de evidencia del laboratorio:

```json
{"Version": "2.D.V03",
 "Analyzer": {"IP": "172.30.30.3", "Name": "Slips", "Model": "1.1.23",
              "Category": ["NIDS"], "Data": ["Flow", "Network"], "Method": ["AI"]},
 "Status": "Event",
 "ID": "ebd07db5-7bce-49cc-9bfa-af59106508ab",
 "Priority": "Low",
 "StartTime": "2026-10-02T06:07:56.258299+00:00",
 "CreateTime": "2026-10-02T06:08:01.904516+00:00",
 "Confidence": 0.1,
 "Description": "Flow with malicious characteristics detected by ml_linear_model. Src IP 10.10.10.12:56080 to 100.64.0.2:80 Threat level: low.",
 "Note": "{\"risk_level\": \"low\", \"uids\": [\"CKF9na2iRjVaETqsUe\"], \"accumulated_threat_level\": 0.02, \"threat_level\": \"low\", \"confidence\": \"low\", \"timewindow\": 1, \"immune_type\": null}",
 "Source": [{"IP": "10.10.10.12", "Port": [56080]}],
 "Target": [{"IP": "100.64.0.2", "Port": [80]}]}
```

| Campo | Tipo | Significado |
|---|---|---|
| `Analyzer.Name` | texto | Siempre `Slips`; identifica la fuente |
| `Status` | texto | `Event` (evidencia) o `Incident` (alerta) |
| `Analyzer.Method` | lista | `Heuristic` o `AI` según el módulo que generó la alerta |
| `ID` | UUID | Identificador único de la alerta |
| `Priority` | texto | Nivel de amenaza: `Info`, `Low`, `Medium`, `High`, `Critical` |
| `Confidence` | número 0–1 | Confianza de Slips en la detección |
| `StartTime` | fecha ISO 8601 | Momento del tráfico que originó la alerta |
| `CreateTime` | fecha ISO 8601 | Momento en que Slips emitió la alerta |
| `Description` | texto | Descripción legible, incluye el módulo o patrón detectado |
| `Source[0].IP` | IP | Entidad que Slips considera atacante |
| `Target[0].IP` | IP | Entidad que Slips considera víctima |
| `Note` | JSON serializado como texto | Incluye `uids` (identificadores de la conexión en Zeek), `timewindow` y `threat_level` |

Cuatro observaciones sobre los 542 registros reunidos en el laboratorio (corridas del 24-09, 25-09 y 02-10):

- Los 542 son evidencias (`Event`). Slips no emitió ninguna alerta: la evidencia acumulada nunca superó su umbral.

- `Priority` coincide siempre con el `threat_level` del campo `Note`, por lo que basta leer `Priority`.
- `Source` y `Target` traen siempre un solo elemento.
- `Source` no es el origen técnico del flujo sino el atacante según Slips. En una evidencia de conexión sospechosa hacia el exterior, `Source` puede ser la IP externa y `Target` el equipo interno. Los puertos sí siguen el orden técnico de la conexión, de modo que no deben usarse para deducir la dirección.

## 2. Por qué no basta el decodificador JSON nativo

La integración actual del laboratorio usa el decodificador JSON que trae Wazuh. Funciona para generar la alerta, pero tiene dos limitaciones comprobadas con `wazuh-logtest`:

- `Source` y `Target` son listas de objetos, y el decodificador las entrega como un texto único (`[{'IP': '10.10.10.1', 'Port': [8]}]`). La IP no queda como campo consultable.
- `Note` es un JSON dentro de un texto, así que `uids` y `timewindow` tampoco quedan disponibles.

La primera es bloqueante para la respuesta: la respuesta activa de Wazuh toma la IP a bloquear del campo `srcip` de la alerta. Sin un `srcip` propio no hay respuesta automática posible.

## 3. Diseño del decodificador

Se define un decodificador propio, `slips`, con decodificadores hijos que extraen cada campo con una expresión regular.

Para que las alertas lleguen al decodificador propio y no al JSON genérico, el recolector les antepone un prefijo. En `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/slips/live/alerts/alerts.json</location>
  <out_format>slips: $(log)</out_format>
</localfile>
```

### Campos de salida

| Campo en Wazuh | Origen en la alerta | Uso |
|---|---|---|
| `srcip` | `Source[0].IP` | Atacante; campo que lee la respuesta activa |
| `slips.status` | `Status` | Distingue evidencia de alerta |
| `dstip` | `Target[0].IP` | Víctima |
| `slips.priority` | `Priority` | Entrada del mapeo de severidad |
| `slips.confidence` | `Confidence` | Entrada del umbral de respuesta |
| `slips.description` | `Description` | Texto de la alerta; conserva el módulo y el patrón detectado |
| `slips.method` | `Analyzer.Method[0]` | Distingue heurística de modelo de aprendizaje |
| `slips.id` | `ID` | Trazabilidad hacia la alerta original |
| `slips.start_time` | `StartTime` | Marca de tiempo del tráfico; base para medir la latencia de detección |
| `slips.uid` | `Note.uids[0]` | Identificador de la conexión en los logs de Zeek |
| `slips.timewindow` | `Note.timewindow` | Ventana temporal del perfil de Slips |

`slips.description`, `slips.method` y `slips.uid` conservan la evidencia que originó cada detección. Con `slips.uid` se llega a la línea exacta de `conn.log`.

Los puertos no se asignan a `srcport` ni `dstport`, por la inconsistencia descrita en la sección 1.

La definición completa está en [td04/local_decoder.xml](td04/local_decoder.xml).

## 4. Mapeo de severidad

Wazuh usa niveles de 0 a 15. Las evidencias se registran con un nivel según su amenaza, para que el analista las vea en contexto. Solo las alertas de Slips quedan como candidatas a respuesta.

| Regla | Condición | Nivel Wazuh | Efecto |
|---|---|---|---|
| 100200 | Cualquier registro de Slips (evidencia `Info`) | 3 | Se registra |
| 100201 | Evidencia `Low` | 5 | Se registra |
| 100202 | Evidencia `Medium` | 7 | Visible en el panel |
| 100203 | Evidencia `High` | 9 | Visible en el panel |
| 100204 | Evidencia `Critical` | 10 | Revisión manual |
| 100210 | Alerta de Slips (`Status` = `Incident`) | 12 | Candidata a respuesta automática (grupo `ndr_respuesta`) |

El umbral de confianza que exige el sistema antes de responder se implementa en dos capas:

1. **En Slips**, que solo emite una alerta cuando la evidencia acumulada del host supera su umbral. Ese umbral es el parámetro que se calibra.
2. **En la matriz de TD05**, que decide qué hacer con cada alerta según el equipo involucrado.

La respuesta automática se asocia al grupo `ndr_respuesta` y no a un nivel, para que subir o bajar niveles no active bloqueos por accidente.

La definición completa está en [td04/local_rules.xml](td04/local_rules.xml).

### Por qué no responder a evidencias

Una primera versión de este diseño disparaba la respuesta ante cualquier evidencia de amenaza alta con confianza mayor o igual a 0,8. Al probarla con los datos del laboratorio, 25 evidencias cumplían esa condición y las 25 eran falsos positivos: 24 por el direccionamiento de la primera corrida y una por la red local que Slips deduce mal (en esta última, el atacante señalado era la puerta de enlace).

El diseño de Slips explica el resultado: ningún módulo decide por sí solo, y una evidencia es un insumo, no una decisión (García et al., 2026). Responder a evidencias aisladas habría anulado precisamente el mecanismo que Slips usa para evitar falsos positivos.

## 5. Validación

El decodificador y las reglas se probaron con `wazuh-logtest` en un contenedor `wazuh-manager` 4.14.7 aislado, usando los 542 registros reunidos:

| Resultado | Cantidad |
|---|---|
| Registros decodificados con `srcip` | 542 de 542 |
| Regla 100200 (nivel 3) | 405 |
| Regla 100201 (nivel 5) | 112 |
| Regla 100203 (nivel 9) | 25 |
| Regla 100210 (respuesta) | 0 |

Como el laboratorio no ha producido alertas de Slips, la regla 100210 se probó con un registro sintético: una evidencia real a la que se cambió `Status` a `Incident`. La regla disparó con nivel 12, grupo `ndr_respuesta` y `srcip` extraído.

Tres alertas de muestra, una por tipo, están en [td04/muestras.json](td04/muestras.json). Para repetir la prueba:

```bash
sed 's/^/slips: /' docs/diseno/td04/muestras.json | docker exec -i <manager> /var/ossec/bin/wazuh-logtest
```

Lo que **no** está validado todavía:

- la estructura de una alerta real de Slips (`Incident`), que puede traer campos distintos a los de una evidencia;
- el paso por el recolector con `out_format` (solo se probó con el probador de reglas);
- registros con IPv6 en `Source` o `Target`;
- evidencias de nivel `Medium` y `Critical`, que no aparecieron en el laboratorio.

## 6. RITA

RITA es un componente complementario y aún no está desplegado en el laboratorio, por lo que esta parte es una especificación provisional, a confirmar cuando se despliegue.

RITA analiza por lotes y entrega sus resultados como filas, no como un flujo de alertas. Se requiere un script intermedio que ejecute la consulta periódicamente, convierta cada fila nueva a una línea JSON y la escriba en un archivo que lea Wazuh con el prefijo `rita: `.

| Campo en Wazuh | Origen en RITA | Uso |
|---|---|---|
| `srcip` | IP de origen del par | Equipo interno que emite el beacon |
| `dstip` | IP de destino del par | Destino del beacon |
| `rita.fqdn` | Nombre de dominio, si existe | Contexto |
| `rita.beacon_score` | Puntaje de beaconing (0–1) | Entrada del mapeo de severidad |
| `rita.severity` | Severidad que asigna RITA | Entrada del mapeo de severidad |
| `rita.connection_count` | Número de conexiones | Evidencia |

En RITA el origen es siempre el equipo interno, así que `srcip` aquí sí es el origen técnico. La diferencia con Slips debe tenerse presente en TD05.

| Regla | Condición | Nivel Wazuh |
|---|---|---|
| 100300 | Cualquier resultado de RITA | 3 |
| 100301 | Puntaje de beaconing ≥ 0,7 | 7 |
| 100302 | Puntaje de beaconing ≥ 0,9 | 10 |

Los resultados de RITA no entran al grupo `ndr_respuesta`: por ser un análisis por lotes, su latencia no es compatible con la respuesta automática y quedan como apoyo a la revisión manual.

Los nombres exactos de las columnas de RITA y los umbrales de puntaje deben verificarse contra la versión que se despliegue.

## 7. Decisiones

| Decisión | Alternativa descartada | Razón |
|---|---|---|
| Decodificador propio con expresiones regulares | Decodificador JSON nativo | El nativo no entrega la IP de `Source` como campo |
| Prefijo `slips: ` con `out_format` | Distinguir por contenido del JSON | El decodificador JSON genérico captura cualquier línea que empiece con `{` |
| `srcip` = atacante según Slips | `srcip` = origen técnico del flujo | Es la entidad que corresponde bloquear y coincide con lo que espera la respuesta activa |
| Respuesta solo ante alertas de Slips | Respuesta ante evidencias con umbral de confianza | Las 25 evidencias que cumplían ese umbral eran falsos positivos; Slips ya agrega la evidencia antes de decidir |
| Respuesta asociada a un grupo de reglas | Respuesta asociada a un nivel | Evita activar bloqueos al ajustar niveles |
| Script intermedio para RITA | Leer la salida de RITA directamente | RITA no emite alertas en línea |
