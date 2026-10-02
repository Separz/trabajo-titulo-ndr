# TD05 — Matriz de decisión de respuesta

Define qué acción se ejecuta ante una alerta, sobre qué equipo, con qué mecanismo y cómo se revierte.

Requisitos relacionados: RF06, RF07, RF09, RF10, RF11. Depende de TD04 (campos `srcip`, `dstip` y grupo `ndr_respuesta`). Insumo para TT10 a TT14.

## 1. Principios

1. **La decisión se toma en un solo lugar.** Wazuh decide y registra toda respuesta. No se usa el bloqueo propio de Slips: el sensor es pasivo y duplicaría la decisión fuera del umbral y del registro auditable.
2. **Toda acción automática es temporal.** Se aplica con un tiempo de expiración y se revierte sola. No hay bloqueos permanentes automáticos.
3. **Ante la duda, decide una persona.** Lo que no cumple todas las condiciones de la matriz pasa a revisión manual.
4. **Hay equipos que nunca se bloquean automáticamente.** Una lista de exclusión protege la infraestructura.

## 2. Entradas de la decisión

| Entrada | De dónde sale | Valores |
|---|---|---|
| Severidad | Regla de Wazuh que dispara (TD04) | Nivel 3 a 13 |
| Entidad amenaza | `srcip` | IP |
| Entidad afectada | `dstip` | IP |
| Ubicación de la amenaza | `srcip` comparada con los rangos internos | Interna o externa |
| Tipo de equipo | ¿Existe un agente Wazuh registrado con esa IP? | Gestionado o no gestionado |
| Exclusión | `srcip` comparada con la lista de exclusión | Excluida o no |

Los rangos internos se declaran en una lista explícita: en el laboratorio, `10.10.10.0/24`; en producción, los rangos del segmento departamental. No se deduce la dirección del tráfico a partir de los puertos.

### Lista de exclusión

Equipos sobre los que nunca se actúa de forma automática, aunque la alerta cumpla el umbral:

- la puerta de enlace y el firewall del segmento;
- los servidores DNS y DHCP;
- los nodos del propio NDR (sensor, Slips, Wazuh);
- los servidores que el Departamento declare críticos.

En Wazuh se implementa con la lista blanca global de la respuesta activa (`white_list`).

La lista no es opcional. En el laboratorio, una de las alertas que alcanzó el nivel de respuesta tenía como entidad amenaza a `10.10.10.1`, la puerta de enlace: sin exclusión, el sistema habría cortado la salida de todo el segmento.

## 3. Mecanismos

| Id | Mecanismo | Dónde se ejecuta | Qué hace | Alcance |
|---|---|---|---|---|
| M0 | Revisión manual | Panel de Wazuh | Muestra la alerta al analista, que decide | Cualquier equipo |
| M1 | Bloqueo perimetral | Firewall del segmento | Agrega la IP a una lista de bloqueo con expiración | Cualquier equipo, con o sin agente |
| M2 | Aislamiento de host | Agente Wazuh del equipo | Corta la red del equipo, salvo la comunicación con el manager | Solo equipos gestionados |

**M1** cubre los equipos sin agente (Wi-Fi, BYOD, IoT). Su límite es que solo afecta el tráfico que cruza el firewall: no detiene el movimiento lateral entre equipos del mismo segmento.

En el laboratorio, M1 corresponde al conjunto `blocklist` de nftables en el nodo `fw`, que ya admite elementos con expiración. En producción hay dos variantes, y la elección depende de lo que admita el firewall institucional:

- un agente Wazuh en el firewall que ejecute el script nativo `firewall-drop`;
- un script propio en el manager que invoque la API del firewall.

**M2** requiere resolver a qué agente corresponde una IP. Las alertas del NDR las genera el manager al leer el archivo de Slips, no el agente del equipo afectado, por lo que la respuesta no puede dirigirse "al agente que originó la alerta". El diseño es un script en el manager que consulta la API de Wazuh por el agente con esa IP y le envía la orden de aislamiento.

## 4. Matriz

Aplica a alertas de Slips. Los resultados de RITA siempre van a M0 (ver TD04, sección 6).

| # | Severidad | Entidad amenaza | Tipo de equipo | Acción | Mecanismo | Reversión |
|---|---|---|---|---|---|---|
| 1 | Nivel menor que 10 | Cualquiera | Cualquiera | Ninguna; se registra | — | — |
| 2 | Nivel 10 a 12 | Cualquiera | Cualquiera | Revisión por el analista | M0 | — |
| 3 | Nivel 13 | En lista de exclusión | Cualquiera | Revisión por el analista, marcada como prioritaria | M0 | — |
| 4 | Nivel 13 | Externa | — | Bloquear la IP externa | M1 | Automática al expirar; manual a pedido |
| 5 | Nivel 13 | Interna | Gestionado | Aislar el equipo y bloquear su IP en el perímetro | M2 + M1 | Automática al expirar; manual a pedido |
| 6 | Nivel 13 | Interna | No gestionado | Bloquear su IP en el perímetro | M1 | Automática al expirar; manual a pedido |
| 7 | Nivel 13 | Interna, y la entidad afectada también es interna | No gestionado | Bloquear en el perímetro y escalar al analista | M1 + M0 | Automática al expirar; manual a pedido |

La fila 7 existe porque M1 no detiene tráfico lateral: si la amenaza y la víctima están en el mismo segmento y el equipo no tiene agente, el bloqueo perimetral solo corta su salida. El analista debe actuar por otra vía, por ejemplo deshabilitando el puerto del switch.

El nivel 13 equivale a severidad alta o crítica con confianza de Slips mayor o igual a 0,8 (regla 100210 de TD04).

## 5. Reversión

| Tipo | Cómo ocurre | Mecanismo |
|---|---|---|
| Automática | Al cumplirse el tiempo de expiración | M1: el elemento expira en la lista de bloqueo. M2: la respuesta activa con estado de Wazuh ejecuta la acción inversa |
| Manual | El analista la solicita antes de la expiración, por un falso positivo | M1: eliminar la IP de la lista de bloqueo. M2: ejecutar la acción inversa del mismo script |

Tiempo de expiración provisional: 10 minutos en el laboratorio. El valor para producción se acuerda con el área responsable de la red.

La reversión manual de M1 ya está probada a mano en el laboratorio (ver README, "Prueba manual de bloqueo con reversión"). La de M2 queda para la implementación.

## 6. Registro auditable

Cada acción y cada reversión deja un registro con tres datos: el detonante (regla y alerta que la originó, con su `slips.id`), el mecanismo usado y la marca de tiempo.

| Fuente | Contenido |
|---|---|
| `active-responses.log` del equipo que ejecuta | Comando, argumentos, alerta de origen y hora de ejecución y de reversión |
| Alertas indexadas en Wazuh | La alerta de origen y las alertas que el ruleset de Wazuh genera al ejecutar y al revertir una respuesta activa |

La alerta de origen y la acción quedan enlazadas por la IP y por el identificador de la alerta.

## 7. Condiciones para habilitar la respuesta automática

La matriz define el comportamiento objetivo. Con los resultados actuales del laboratorio, la respuesta automática **no debe habilitarse todavía**:

- Las 25 alertas que alcanzaron el nivel 13 son falsos positivos (TD04, sección 5).
- Slips no clasifica el beacon simulado como canal de mando y control.

Antes de activar las filas 4 a 7 deben cumplirse tres condiciones:

1. Slips calibrado, con la red local declarada correctamente y una tasa de falsos positivos medida sobre tráfico benigno.
2. Umbral de confianza revisado con los resultados de esa calibración.
3. Lista de exclusión cargada y probada.

Mientras tanto, todas las alertas de nivel 10 o superior se tratan con la fila 2.

En producción se agrega una cuarta condición: la autorización del área responsable de la red para cada mecanismo.

## 8. Decisiones

| Decisión | Alternativa descartada | Razón |
|---|---|---|
| Wazuh como único punto de decisión | Bloqueo nativo de Slips | El sensor es pasivo y se perdería el umbral y el registro centralizados |
| Lista explícita de rangos internos | Deducir la dirección por puertos o por el orden de los campos | El orden de `Source` y `Target` en IDEA no indica dirección |
| Lista de exclusión obligatoria | Confiar solo en el umbral | Un falso positivo sobre la puerta de enlace cortaría todo el segmento |
| M2 mediante script en el manager y la API | Respuesta activa dirigida al agente de origen | Las alertas del NDR se originan en el manager, no en el agente afectado |
| Dos variantes de M1 para producción | Fijar una | Depende de si el firewall institucional admite un agente o solo expone una API |
| RITA solo a revisión manual | Respuesta automática por puntaje de beaconing | Analiza por lotes; su latencia no es compatible con una respuesta inmediata |
