# TD04 — Especificación del decodificador de alertas

Define cómo las detecciones de Slips y de RITA se convierten en eventos de Wazuh: qué campos se extraen, a qué campos de Wazuh se asignan y qué nivel de severidad recibe cada una.

Requisitos relacionados: RF05, RF11, RNF09. Insumo para TD05 y para la implementación TT05a, TT05b y TT10.

Referencia principal: García, S. et al. (2026). *Slips: Behavioral Evidence Aggregation for Network Security*. arXiv:2608.11979. El resto de las fuentes está en la sección 8.

## 1. Entrada: alerta de Slips

Slips 1.1.23 escribe un registro por línea en `alerts.json`, en formato IDMEFv2 (versión `2.D.V03`). Hay dos tipos de registro, que se distinguen por el campo `Status` (García et al., 2026):

- **`Event`: evidencia.** La interpretación que hace un módulo de detección de una o más conexiones. Una evidencia aislada no es una decisión.
- **`Incident`: alerta.** Slips suma la evidencia de cada host dentro de una ventana de tiempo, ponderando nivel de amenaza por confianza; cuando la suma supera el umbral configurado, emite una alerta sobre ese host.

El borrador IDMEFv2 define `Incident` como un evento que «is considered as an incident and should be taken care of» (sección 5.2, tabla 3).

### Evidencia

Ejemplo real del laboratorio:

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
| `Analyzer.Method` | lista | `Heuristic` o `AI` según el módulo que generó la evidencia |
| `ID` | UUID | Identificador único del registro |
| `Priority` | texto | Nivel de amenaza: `Info`, `Low`, `Medium` o `High` (ver la nota sobre el nivel crítico) |
| `Confidence` | número 0–1 | Confianza de Slips en la detección |
| `StartTime` | fecha ISO 8601 | Momento del tráfico que originó la evidencia |
| `CreateTime` | fecha ISO 8601 | Momento en que Slips emitió el registro |
| `Description` | texto | Descripción legible, incluye el módulo o patrón detectado |
| `Source[0].IP` | IP | Entidad que Slips considera atacante |
| `Target[0].IP` | IP | Entidad que Slips considera víctima |
| `Note` | JSON serializado como texto | Incluye `uids` (identificadores de la conexión en Zeek), `timewindow` y `threat_level` |

### Alerta

Una alerta trae menos campos que una evidencia. Ejemplo real de la corrida del 13-10, con la lista `CorrelID` abreviada (el registro original trae 34 identificadores):

```json
{"Version": "2.D.V03",
 "Analyzer": {"IP": "0.0.0.0", "Name": "Slips", "Model": "1.1.23",
              "Category": ["NIDS"], "Data": ["Flow", "Network"], "Method": ["Heuristic"]},
 "Source": [{"IP": "10.10.10.12"}],
 "ID": "3b781b2b-44bf-47ff-b949-7a0f19723aa8",
 "Status": "Incident",
 "StartTime": "2026-10-13T06:01:07.514338+00:00",
 "CreateTime": "2026-10-13T06:58:31.487742+00:00",
 "CorrelID": ["f4f57c35-a955-4741-9880-e54bedfebe20", "b65dfe25-e1ad-4fd6-92f5-49ffeba656d9"],
 "Note": "{\"accumulated_threat_level\": 3.0200000000000005, \"accumulated_ratl\": 5.194400000000001, \"risk_level\": \"high\", \"timewindow\": 2, \"EndTime\": \"2026-10-13T07:01:07.514338+00:00\"}"}
```

- `Source[0].IP` es el host sobre el que Slips decide.
- `CorrelID` lista los `ID` de las evidencias que originaron la alerta.
- `StartTime` y el `EndTime` de `Note` delimitan la ventana de tiempo.
- No trae `Priority`, `Confidence`, `Description` ni `Target`.

Esta estructura coincide con el código que la genera (`slips_files/common/idmefv2.py`, líneas 146-177) y con las 1.242 alertas observadas en el laboratorio (801 el 09-10 y 441 el 13-10).

### Observaciones

Sobre los 542 registros de las primeras corridas (24-09, 25-09 y 02-10):

- Los 542 son evidencias. En esas corridas Slips no emitió ninguna alerta; las primeras aparecieron el 09-10, con un escaneo de puertos desde `pc2`.
- `Source` y `Target` traen siempre un solo elemento.
- `Source` no es el origen técnico del flujo sino el atacante según Slips. En una evidencia de conexión sospechosa hacia el exterior, `Source` puede ser la IP externa y `Target` el equipo interno. Los puertos sí siguen el orden técnico de la conexión, de modo que no deben usarse para deducir la dirección.

Sobre el código de Slips 1.1.23:

- **`Priority` nunca vale `Critical`.** IDMEFv2 solo define `Unknown`, `Info`, `Low`, `Medium` y `High` (borrador, sección 5.2, tabla 4), y Slips convierte su nivel crítico a `High` al escribir el registro (`idmefv2.py`, líneas 80-93). El nivel original se conserva en `threat_level`, dentro de `Note` (`slips_files/core/evidence_handler_worker.py`, línea 143). En los demás niveles, `Priority` y `threat_level` coinciden.
- **`Source` y `Target` no siempre contienen una IP.** Según el tipo de entidad pueden traer `Hostname` o `URL` (`idmefv2.py`, líneas 111-116). En todas las evidencias del laboratorio fueron IP.
- **`Target` es opcional en una evidencia** (`idmefv2.py`, línea 262). En el laboratorio apareció en todas.
- **Slips escribe el JSON con espacios** después de `:` y `,` (`slips_files/core/evidence_logger.py`, línea 98). Importa para la sección 3.

## 2. Por qué no basta el decodificador JSON nativo

La primera integración del laboratorio usaba el decodificador JSON que trae Wazuh. Funcionaba para generar la alerta, pero tenía dos limitaciones comprobadas con `wazuh-logtest`:

- `Source` y `Target` son listas de objetos, y el decodificador las entrega como un texto único (`[{'IP': '10.10.10.1', 'Port': [8]}]`). La IP no queda como campo consultable. La documentación de Wazuh lo declara: «An array of objects is not supported» (*JSON decoder*).
- `Note` es un JSON dentro de un texto, así que `uids`, `timewindow` y `threat_level` tampoco quedan como campos.

La primera es bloqueante para la respuesta: los scripts de respuesta activa de Wazuh toman la IP a bloquear del campo `srcip` de la alerta (`src/active-response/active_responses.c`, función `get_srcip_from_json`). Sin un `srcip` propio no hay respuesta automática posible, y la alerta tampoco puede decir sobre qué equipo es.

## 3. Diseño del decodificador

Se define un decodificador propio, `slips`, que combina dos mecanismos:

- el **plugin JSON de Wazuh**, que extrae todos los campos simples con su nombre original;
- **dos expresiones regulares**, que extraen lo que el plugin no puede: la IP de `Source` y la de `Target`.

Wazuh documenta esta combinación («the ability to combine plugin decoders with regular expressions», *JSON decoder*) y la usa en su propio ruleset para obtener `srcip` de un registro JSON (`ruleset/decoders/0010-active-response_decoders.xml`, decodificador `ar_log_json_child`).

Para que los registros lleguen al decodificador propio y no al JSON genérico, el recolector les antepone un prefijo. En `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/ossec/logs/slips/live/alerts/alerts.json</location>
  <out_format>slips: $(log)</out_format>
</localfile>
```

El decodificador tiene cuatro partes:

```xml
<decoder name="slips">
  <prematch>^slips: </prematch>
</decoder>

<decoder name="slips_campos">
  <parent>slips</parent>
  <prematch>^slips: </prematch>
  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="slips_campos">
  <parent>slips</parent>
  <regex type="pcre2">"Source":\s*\[\{"IP":\s*"([^"]+)"</regex>
  <order>srcip</order>
</decoder>

<decoder name="slips_campos">
  <parent>slips</parent>
  <regex type="pcre2">"Target":\s*\[\{"IP":\s*"([^"]+)"</regex>
  <order>dstip</order>
</decoder>
```

- El padre reconoce las líneas por el prefijo.
- El primer hijo repite el `prematch` y usa `offset="after_prematch"` para que el plugin empiece a leer el JSON después del prefijo. Con `offset="after_parent"` el plugin no extrajo ningún campo.
- Los tres hijos comparten nombre para que Wazuh los aplique todos al mismo registro.
- Las expresiones exigen que la primera clave de `Source` o `Target` sea `IP`. Si Slips informa un `Hostname` o una `URL`, no se crea `srcip` y no hay respuesta posible sobre ese registro.

### Espacios en el JSON

Las expresiones usan `:\s*` porque el texto que llega al decodificador no es el que escribe Slips. Slips escribe `"Source": [{"IP": "10.10.10.12"}]`, con espacios. El recolector de Wazuh, con `log_format json`, interpreta cada línea y la vuelve a escribir en forma compacta, sin espacios (`src/logcollector/read_json.c`, llamada a `cJSON_PrintUnformatted`). El probador `wazuh-logtest`, en cambio, recibe la línea tal como se le entrega.

Una expresión escrita para una sola de las dos formas funciona en el probador y falla en producción, o al revés. Se comprobó en el manager: el campo `full_log` de las alertas empieza con `slips: {"Version":"2.D.V03","Analyzer":{`, sin espacios.

### Campos de salida

| Campo en Wazuh | Origen en el registro | Mecanismo | Uso |
|---|---|---|---|
| `srcip` | `Source[0].IP` | Expresión regular | Atacante; campo que lee la respuesta activa |
| `dstip` | `Target[0].IP` | Expresión regular | Víctima; solo en evidencias |
| `Status` | `Status` | Plugin JSON | Distingue evidencia de alerta |
| `Priority` | `Priority` | Plugin JSON | Entrada del mapeo de severidad |
| `Confidence` | `Confidence` | Plugin JSON | Confianza de la evidencia |
| `Description` | `Description` | Plugin JSON | Texto de la alerta; conserva el módulo y el patrón detectado |
| `Analyzer.Name`, `Analyzer.Method` | `Analyzer` | Plugin JSON | Identifica la fuente; distingue heurística de modelo de aprendizaje |
| `ID` | `ID` | Plugin JSON | Trazabilidad hacia el registro original |
| `StartTime`, `CreateTime` | Ídem | Plugin JSON | Base para medir la latencia de detección |
| `CorrelID` | `CorrelID` | Plugin JSON | Evidencias que originaron una alerta |
| `Note` | `Note` | Plugin JSON, como texto | Contiene `threat_level`, `uids` y `timewindow` |

`srcip` y `dstip` son campos estáticos de Wazuh; el resto son campos dinámicos (*Decoders syntax*, opción `order`).

`uids` y `timewindow` no quedan como campos propios: siguen dentro del texto de `Note`. Con `uids` se llega a la línea exacta de `conn.log` en Zeek. Si se necesitan como campos, basta agregar un decodificador hijo con una expresión regular por cada uno.

Los puertos no se asignan a `srcport` ni `dstport`, por la inconsistencia descrita en la sección 1.

La definición completa está en [td04/local_decoder.xml](td04/local_decoder.xml), que es copia de `configs/wazuh/local_decoder.xml`.

## 4. Mapeo de severidad

Wazuh usa niveles de 0 a 15. Las evidencias se registran con un nivel según su amenaza, para que el analista las vea en contexto. Solo las alertas de Slips quedan como candidatas a respuesta.

| Regla | Condición | Nivel Wazuh | Efecto |
|---|---|---|---|
| 100200 | Cualquier registro de Slips (evidencia `Info`) | 3 | Se registra |
| 100201 | Evidencia `Low` | 5 | Se registra |
| 100202 | Evidencia `Medium` | 7 | Visible en el panel |
| 100203 | Evidencia `High` | 9 | Visible en el panel |
| 100204 | Evidencia `High` cuyo `threat_level` en `Note` es `critical` | 10 | Revisión manual |
| 100210 | Alerta de Slips (`Status` = `Incident`) | 12 | Candidata a respuesta automática (grupo `ndr_respuesta`) |

Dos reglas no usan la condición más directa:

- **100204** depende de la 100203 y lee `Note`, porque una evidencia crítica llega con `Priority` = `High` (sección 1).
- **100210** busca el texto `"Status":\s*"Incident"` en el registro en vez de consultar el campo `Status`. Wazuh no admite `<field name="Status">`: `status` es un nombre de campo estático reservado y la carga de reglas falla con «Field 'Status' is static». La expresión tolera el espacio por la razón descrita en la sección 3.

El umbral de confianza que exige el sistema antes de responder se implementa en dos capas:

1. **En Slips**, que solo emite una alerta cuando la evidencia acumulada del host supera su umbral. Ese umbral es el parámetro que se calibra.
2. **En la matriz de TD05**, que decide qué hacer con cada alerta según el equipo involucrado.

La respuesta automática se asocia al grupo `ndr_respuesta` y no a un nivel, para que subir o bajar niveles no active bloqueos por accidente.

La definición completa está en [td04/local_rules.xml](td04/local_rules.xml), que es copia de `configs/wazuh/local_rules.xml`.

### Por qué no responder a evidencias

Una primera versión de este diseño disparaba la respuesta ante cualquier evidencia de amenaza alta con confianza mayor o igual a 0,8. Al probarla con los datos del laboratorio, 25 evidencias cumplían esa condición y las 25 eran falsos positivos: 24 por el direccionamiento de la primera corrida y una por la red local que Slips deduce mal (en esta última, el atacante señalado era la puerta de enlace).

El diseño de Slips explica el resultado: ningún módulo decide por sí solo, y una evidencia es un insumo, no una decisión (García et al., 2026). Responder a evidencias aisladas habría anulado precisamente el mecanismo que Slips usa para evitar falsos positivos.

## 5. Validación

Versiones: `wazuh-manager` 4.14.7 y Slips 1.1.23. El 14-10 se repitió la validación en vivo con Slips 1.1.24: los 5.360 registros de una corrida llegaron a Wazuh, todos con `srcip`, en las mismas reglas según su tipo. El formato de `alerts.json` no cambió entre versiones (`idmefv2.py` y `evidence_logger.py` son idénticos).

### Con el probador de reglas

El decodificador y las reglas se probaron primero con `wazuh-logtest` en un contenedor `wazuh-manager` aislado, con registros reales del 09-10. Una alerta, una evidencia `Low` y una evidencia `High` dispararon las reglas 100210, 100201 y 100203, con `srcip` y `dstip` extraídos, tanto en la forma compacta del JSON como en la forma con espacios.

Cuatro registros de muestra, tres evidencias y una alerta, están en [td04/muestras.json](td04/muestras.json). Para repetir la prueba:

```bash
sed 's/^/slips: /' docs/diseno/td04/muestras.json | docker exec -i <manager> /var/ossec/bin/wazuh-logtest
```

El resultado esperado es, en orden, las reglas 100201, 100203, 100200 y 100210.

### En vivo

El 13-10 se validó el flujo completo en el manager del laboratorio: Slips escribe `alerts.json`, el recolector lo lee con `out_format` y el manager decodifica y clasifica. Hubo dos corridas de Slips. La primera, solo con el beacon de `pc2`, produjo 233 registros. La segunda, con un escaneo de puertos desde `pc2` hacia `pc1` (`nmap -sS -p 1-2000 10.10.10.11`), produjo 10.798.

| Tipo de registro | Slips escribió | Wazuh recibió | Regla (nivel) |
|---|---|---|---|
| Evidencia `Info` | 2.452 | 2.452 | 100200 (3) |
| Evidencia `Low` | 6.132 | 6.132 | 100201 (5) |
| Evidencia `Medium` | 1 | 1 | 100202 (7) |
| Evidencia `High` | 2.005 | 2.005 | 100203 (9) |
| Alerta | 441 | 441 | 100210 (12) |
| **Total** | **11.031** | **11.031** | |

- Las 11.031 alertas de Wazuh traen `srcip`.
- 10.590 traen `dstip`: todas las evidencias. Las 441 alertas de Slips no lo traen porque no tienen `Target`.
- Las 441 alertas de Slips son sobre `10.10.10.12`. En Wazuh quedaron con nivel 12, grupo `ndr_respuesta` y la descripción «Slips: alerta sobre el equipo 10.10.10.12».
- No hubo errores ni advertencias del recolector en el log del manager.

La columna de Slips suma las dos corridas. El desglose de la segunda sale del archivo `alerts.json` respaldado. De la primera solo se conserva el total (233), porque Slips borra el archivo al arrancar; su desglose (195 `Info`, 37 `Low` y una `High`) es el que registró Wazuh.

La regla 100204 se probó con un registro sintético, porque el laboratorio no ha producido evidencias críticas: una evidencia `High` real a la que se cambió `threat_level` de `high` a `critical`. El registro original disparó la 100203 (nivel 9) y el modificado la 100204 (nivel 10).

### Hallazgos de la corrida en vivo

- **Slips repite la alerta.** Emitió 441 alertas sobre el mismo host en menos de ocho minutos (06:58 a 07:06 UTC), todas en la misma ventana de tiempo. Cada una sería un disparo de la respuesta. Falta una regla que agrupe las repeticiones por `srcip`. Son dos fenómenos distintos:
  - **Copias.** Solo hay 152 conjuntos distintos de evidencias (`CorrelID`): 143 aparecen tres veces, 3 dos veces y 6 una vez, en el mismo segundo y con distinto `ID`. Son 289 copias. El 09-10 ocurrió lo mismo (306 alertas distintas, 230 por triplicado). La causa es una condición de carrera: Slips procesa las evidencias con tres procesos en paralelo (`DEFAULT_EVIDENCE_HANDLER_WORKERS = 3`, `slips_files/core/evidence_handler.py`, línea 48; también visibles como `evidence_worker_1` a `_3` en la salida de arranque) y en la 1.1.23 nada coordina la decisión de alertar. Slips 1.1.24 lo corrige («Fix duplicate alerts» en su lista de cambios): agrega `try_claim_alert_generation` (`alert_handler.py`, línea 63), que usa una operación atómica de Redis para que un solo proceso genere la alerta de un perfil y ventana, con un comentario que describe exactamente este caso. Se comprobó en vivo el 14-10, sobre el mismo escaneo: la 1.1.23 escribió 67 alertas (22 por triplicado) y la 1.1.24, 14 alertas sin ninguna copia. Por eso se adoptó la 1.1.24 (TD06, punto abierto 8). La 1.1.24 emitió además menos alertas distintas (14 contra 23), porque sus dos modelos de aprendizaje marcaron unos 350 flujos menos cada uno; la causa de esa diferencia no se investigó, y `ml_online_model` aprende durante la ejecución, así que puede variar entre corridas.
  - **Alertas sucesivas.** Después de cada alerta, Slips descarta las evidencias que ya la formaron y vuelve a acumular (`evidence_handler_worker.py`, líneas 237-282); con el escaneo, el umbral se vuelve a superar cada uno o dos segundos. Es su funcionamiento normal cuando su bloqueo propio está desactivado, porque ese bloqueo es lo que corta las alertas siguientes (`handle_new_alert`, líneas 365-399).
- **2.000 de las 2.004 evidencias `High` de la segunda corrida son falsos positivos.** Señalan a `pc1`, el equipo escaneado, como atacante, por «conexión a una IP privada fuera de la red local». La causa es la red local que Slips deduce mal (TD05, sección 7). Tres describen el escaneo real y la restante señala a la puerta de enlace por el mismo motivo. Las evidencias de ese tipo aportaron cerca del 83 % del puntaje que disparó las alertas sobre `pc2`, contra un 0,5 % de la detección del escaneo, en una estimación de nivel de amenaza por confianza.
- **Con la red local corregida, ambos efectos se reducen.** En una corrida aislada sobre los mismos logs, con la interfaz virtual de TD06 («Red local de Slips»), desaparecieron las evidencias de conexión fuera de la red local, quedaron 3 evidencias `High` (las del escaneo) y Slips emitió 54 alertas en vez de 441: 18 distintas, cada una por triplicado.

### Lo que no está validado todavía

- una evidencia crítica real;
- registros con IPv6, `Hostname` o `URL` en `Source` o `Target`;
- el comportamiento del recolector ante ráfagas mayores: en una prueba aislada en que se volcaron 20.937 registros de una sola vez, el recolector informó «message queue is full» y se perdieron 2.606. En la corrida en vivo, con Slips escribiendo a su ritmo, no se perdió ninguno.

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
| Decodificador propio que combina el plugin JSON con expresiones regulares | Decodificador JSON nativo | El nativo no entrega la IP de `Source` como campo |
| Plugin JSON para los campos simples | Una expresión regular por campo | Menos expresiones que mantener; los campos conservan su nombre original y los campos nuevos de Slips aparecen sin cambiar el decodificador |
| Prefijo `slips: ` con `out_format` | Distinguir por contenido del JSON | El decodificador JSON genérico captura cualquier línea que empiece con `{` |
| Expresiones que toleran espacios (`:\s*`) | Expresiones para una sola forma del JSON | El recolector compacta el JSON y el probador de reglas no; una sola forma falla en uno de los dos |
| `srcip` = atacante según Slips | `srcip` = origen técnico del flujo | Es la entidad que corresponde bloquear y coincide con lo que espera la respuesta activa |
| Nivel crítico leído de `Note` | Leerlo de `Priority` | Slips escribe `High` en `Priority` para el nivel crítico |
| Alerta detectada por texto (`match`) | Consultar el campo `Status` | Wazuh reserva `status` como campo estático y no lo admite en `<field>` |
| Red local de Slips declarada con una interfaz virtual (detalle en TD06) | Analizar con `-f`, donde `client_ips` se respeta | Con `-g` Slips ignora `client_ips`; `-f` es por lotes y su latencia no es compatible con la respuesta automática |
| Respuesta solo ante alertas de Slips | Respuesta ante evidencias con umbral de confianza | Las 25 evidencias que cumplían ese umbral eran falsos positivos; Slips ya agrega la evidencia antes de decidir |
| Respuesta asociada a un grupo de reglas | Respuesta asociada a un nivel | Evita activar bloqueos al ajustar niveles |
| Script intermedio para RITA | Leer la salida de RITA directamente | RITA no emite alertas en línea |

## 8. Fuentes

Formato de los registros:

- *The Incident Detection Message Exchange Format version 2 (IDMEFv2)*, borrador IETF `draft-lehmann-idmefv2-03`. https://www.ietf.org/archive/id/draft-lehmann-idmefv2-03.txt
- Código de Slips 1.1.23, https://github.com/stratosphereips/StratosphereLinuxIPS: `slips_files/common/idmefv2.py`, `slips_files/core/evidence_handler_worker.py` y `slips_files/core/evidence_logger.py`. Los números de línea citados corresponden a esa versión. En la 1.1.24, adoptada el 14-10, `idmefv2.py`, `evidence_logger.py` y `localnet_handler.py` no cambiaron; `evidence_handler_worker.py` sí, y algunas referencias se desplazan: `threat_level` pasa de la línea 143 a la 144, `get_evidence_that_were_part_of_a_past_alert` de la 237 a la 239, `get_evidence_for_tw` de la 253 a la 255 y `handle_new_alert` de la 365 a la 384.

Wazuh:

- *Decoders syntax*. https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html
- *JSON decoder*. https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html
- Referencia de `localfile` (`out_format`). https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html
- Referencia de `active-response` y de `commands`. https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html y https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/commands.html
- Código de Wazuh, https://github.com/wazuh/wazuh: `src/logcollector/read_json.c` y `src/active-response/active_responses.c`, revisados en la etiqueta v4.14.1. El comportamiento del recolector se confirmó además en la versión 4.14.7 del laboratorio.
- Ruleset instalado en el manager: `/var/ossec/ruleset/decoders/0010-active-response_decoders.xml`.
