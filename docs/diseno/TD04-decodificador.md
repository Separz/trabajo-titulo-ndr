# TD04 — Especificación del decodificador de alertas

Define cómo las detecciones de Slips y de RITA se convierten en eventos de Wazuh: qué campos se extraen, a qué campos de Wazuh se asignan y qué nivel de severidad recibe cada una.

Requisitos relacionados: RF05, RF11, RNF09. Insumo para TD05 y para la implementación TT05a, TT05b y TT10.

## 1. Entrada: alerta de Slips

Slips 1.1.23 escribe una alerta por línea en `alerts.json`, en formato IDEA (versión `2.D.V03`). Ejemplo real del laboratorio:

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
| `Analyzer.Method` | lista | `Heuristic` o `AI` según el módulo que generó la alerta |
| `ID` | UUID | Identificador único de la alerta |
| `Priority` | texto | Nivel de amenaza: `Info`, `Low`, `Medium`, `High`, `Critical` |
| `Confidence` | número 0–1 | Confianza de Slips en la detección |
| `StartTime` | fecha ISO 8601 | Momento del tráfico que originó la alerta |
| `CreateTime` | fecha ISO 8601 | Momento en que Slips emitió la alerta |
| `Description` | texto | Descripción legible, incluye el módulo o patrón detectado |
| `Source[0].IP` | IP | Entidad que Slips considera la amenaza (semántica IDEA) |
| `Target[0].IP` | IP | Entidad afectada |
| `Note` | JSON serializado como texto | Incluye `uids` (identificadores de la conexión en Zeek), `timewindow` y `threat_level` |

Tres observaciones sobre las 503 alertas reunidas en el laboratorio (corridas del 24-09, 25-09 y 02-10):

- `Priority` coincide siempre con el `threat_level` del campo `Note`, por lo que basta leer `Priority`.
- `Source` y `Target` traen siempre un solo elemento.
- En IDEA, `Source` no es el origen técnico del flujo sino la entidad maliciosa. En una alerta de conexión sospechosa hacia el exterior, `Source` puede ser la IP externa y `Target` el equipo interno. Los puertos sí siguen el orden técnico de la conexión, de modo que no deben usarse para deducir la dirección.

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
| `srcip` | `Source[0].IP` | Entidad amenaza; campo que lee la respuesta activa |
| `dstip` | `Target[0].IP` | Entidad afectada |
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

Wazuh usa niveles de 0 a 15. El mapeo parte del nivel de amenaza de Slips y agrega un nivel reservado para las alertas que cumplen el umbral de respuesta.

| Regla | Condición | Nivel Wazuh | Efecto |
|---|---|---|---|
| 100200 | Cualquier alerta de Slips (`Info`) | 3 | Se registra |
| 100201 | `Priority` = `Low` | 5 | Se registra |
| 100202 | `Priority` = `Medium` | 7 | Visible en el panel |
| 100203 | `Priority` = `High` | 10 | Revisión manual |
| 100204 | `Priority` = `Critical` | 12 | Revisión manual |
| 100210 | `High` o `Critical`, y `Confidence` ≥ 0,8 | 13 | Candidata a respuesta automática (grupo `ndr_respuesta`) |

El umbral de 0,8 es provisional. La regla 100210 es el único punto donde se define, de modo que calibrarlo implica cambiar una sola expresión.

La respuesta automática se asocia al grupo `ndr_respuesta` y no a un nivel, para que subir o bajar niveles no active bloqueos por accidente.

La definición completa está en [td04/local_rules.xml](td04/local_rules.xml).

## 5. Validación

El decodificador y las reglas se probaron con `wazuh-logtest` en un contenedor `wazuh-manager` 4.14.7 aislado, usando las 503 alertas reunidas:

| Resultado | Cantidad |
|---|---|
| Alertas decodificadas con `srcip` | 503 de 503 |
| Regla 100200 (nivel 3) | 376 |
| Regla 100201 (nivel 5) | 102 |
| Regla 100210 (nivel 13) | 25 |

Tres alertas de muestra, una por tipo, están en [td04/muestras.json](td04/muestras.json). Para repetir la prueba:

```bash
sed 's/^/slips: /' docs/diseno/td04/muestras.json | docker exec -i <manager> /var/ossec/bin/wazuh-logtest
```

**Hallazgo.** Las 25 alertas que alcanzan el nivel 13 son falsos positivos conocidos del laboratorio: 24 por el direccionamiento de la primera corrida (ya corregido) y 1 por la red local que Slips deduce mal. Con el umbral actual, todas habrían disparado un bloqueo. Esto confirma que `Priority` y `Confidence` de una alerta aislada no bastan como criterio de respuesta, y condiciona el diseño de TD05: lista de exclusión obligatoria y calibración de Slips antes de habilitar la respuesta automática.

Lo que **no** está validado todavía:

- el paso por el recolector con `out_format` (solo se probó con el probador de reglas);
- alertas con IPv6 en `Source` o `Target`;
- alertas de nivel `Medium` y `Critical`, que no aparecieron en el laboratorio.

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
| `srcip` = entidad amenaza de IDEA | `srcip` = origen técnico del flujo | Es la entidad que corresponde bloquear y coincide con lo que espera la respuesta activa |
| Respuesta asociada a un grupo de reglas | Respuesta asociada a un nivel | Evita activar bloqueos al ajustar niveles |
| Script intermedio para RITA | Leer la salida de RITA directamente | RITA no emite alertas en línea |
