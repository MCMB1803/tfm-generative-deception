# 05. Integración con SIEM (Wazuh / ELK)

> **Estado: desplegado y validado contra un manager real.** Wazuh 4.9.2 forma
> parte de `docker-compose.yml` bajo el perfil `siem`, y `siem/validate_rules.py`
> comprueba, pasando eventos reales por `wazuh-logtest`, que **las 10 reglas
> disparan el identificador y el nivel que declara este diseño**. La evidencia
> se regenera en `benchmarks/results/SIEM_VALIDATION.md`.
>
> Lo que sigue **sin** validar, y debe declararse así en la memoria: el
> transporte desde un agente remoto hasta el manager y la visualización en el
> panel, que dependen del despliegue concreto.

```bash
docker compose --profile siem up -d
python siem/validate_rules.py
```

Las reglas versionadas viven en `siem/wazuh/local_rules.xml`. Los bloques XML de
este documento son su explicación; **el fichero es la fuente de verdad**, porque
es el que se carga y el que se prueba.

## Defectos que solo aparecieron al probarlas

Las reglas estaban escritas pero nunca se habían ejecutado. Tres no funcionaban:

| Defecto | Consecuencia | Corrección |
|---|---|---|
| La regla base usaba `<decoded_as>json</decoded_as>` | La regla **86600** del conjunto oficial («Suricata messages») captura cualquier JSON con los campos `timestamp` y `event_type`, que es la firma exacta de estos eventos. Al ser hermanas, el análisis se detenía ahí y **ninguna regla propia llegaba a evaluarse**: el SIEM no alertaba de nada. | Encadenarla con `<if_sid>86600</if_sid>`. |
| `<field name="honeytokens">\.+</field>` | El decodificador JSON convierte un `null` en la cadena literal `'null'`, que `\.+` da por buena. La regla disparaba **nivel 15 en cada comando ejecutado**, convirtiendo la señal de mayor valor del sistema en ruido constante. | Comparar contra el formato del identificador (`HT-[0-9A-F]{6,}`) y omitir el campo en el emisor cuando está vacío. |
| `<field name="src_ip">` con anclas y alternancia | `<field>` usa OS_Regex por defecto, que no admite `^`, `$` ni `(a\|b)`. El fichero entero se rechazaba y **el manager no arrancaba**. | Declarar `type="pcre2"`. |

---

## 1. Formato de Eventos

El framework escribe **JSON Lines**: un objeto JSON por línea, claves planas, marcas de tiempo ISO-8601 en UTC. Es el formato que el decodificador JSON de Wazuh y Filebeat ingieren sin *parser* propio.

| Fichero | Contenido |
|---|---|
| `/app/data/logs/deception-events.jsonl` | Eventos SOC: sesiones, credenciales, comandos, alertas operativas. |
| `/app/data/logs/latency.jsonl` | Telemetría de rendimiento. Fuente del capítulo 4, **no** para el SIEM. |

### Tipos de evento

| `event_type` | Severidad | Significado |
|---|---|---|
| `session.opened` | high (12) | Conexión entrante al señuelo. |
| `auth.attempt` | high (12) | Credenciales capturadas, en claro. |
| `command.executed` | low–critical (5–14) | Comando ejecutado. Severidad según técnica ATT&CK. |
| `session.closed` | según sesión | Resumen: comandos, duración, técnicas observadas. |
| `system.ready` | — | Arranque del orquestador. |
| `system.latency_breach` | medium (8) | Respuesta por encima del objetivo: riesgo de *fingerprinting* temporal. |
| `system.inference_degraded` | medium (8) | El motor de inferencia no responde. |
| `artifacts.built` | — | Artefactos generados. |

Los campos `severity`, `wazuh_level` y `confidence` vienen ya calculados por el Agente de Alertas. `confidence` es siempre `confirmed` para eventos de intrusión: toda interacción con el señuelo es no autorizada por construcción.

---

## 2. Exposición de los Logs al Agente de Wazuh

El volumen `agent_data` debe ser legible por el agente de Wazuh del host. Añade un *bind mount* al servicio `deception-agent` en `docker-compose.yml`:

```yaml
  deception-agent:
    volumes:
      - agent_data:/app/data
      - ./data/logs:/app/data/logs      # <-- accesible desde el host
```

---

## 3. Configuración del Agente de Wazuh

En `/var/ossec/etc/ossec.conf` del host donde corre la pila:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/ruta/al/repo/data/logs/deception-events.jsonl</location>
</localfile>
```

Reiniciar: `sudo systemctl restart wazuh-agent`

---

## 4. Reglas de Correlación

En el manager, `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="deception,generative_deception,">

  <!-- Regla base: cualquier evento del framework -->
  <rule id="100200" level="0">
    <decoded_as>json</decoded_as>
    <field name="product">generative-deception-framework</field>
    <description>Generative Deception Framework: evento</description>
  </rule>

  <!-- Conexion al senuelo. Nivel 12 fijo: no hay motivo legitimo. -->
  <rule id="100201" level="12">
    <if_sid>100200</if_sid>
    <field name="event_type">session.opened</field>
    <description>CIBERENGANO: conexion no autorizada al senuelo SSH desde $(src_ip)</description>
    <mitre><id>T1021.004</id></mitre>
  </rule>

  <!-- Credenciales capturadas -->
  <rule id="100202" level="12">
    <if_sid>100200</if_sid>
    <field name="event_type">auth.attempt</field>
    <description>CIBERENGANO: credenciales capturadas - usuario '$(username)' desde $(src_ip)</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- Comandos: severidad segun la clasificacion ATT&CK del framework -->
  <rule id="100210" level="8">
    <if_sid>100200</if_sid>
    <field name="event_type">command.executed</field>
    <description>CIBERENGANO: comando en el senuelo - $(command)</description>
  </rule>

  <rule id="100211" level="12">
    <if_sid>100210</if_sid>
    <field name="severity">high</field>
    <description>CIBERENGANO: reconocimiento avanzado - $(command)</description>
  </rule>

  <rule id="100212" level="14">
    <if_sid>100210</if_sid>
    <field name="severity">critical</field>
    <description>CIBERENGANO CRITICO: acceso a credenciales o evasion - $(command)</description>
  </rule>

  <!-- Honeytoken leido: la senal de mayor valor del sistema -->
  <rule id="100213" level="15">
    <if_sid>100210</if_sid>
    <field name="honeytokens">\.+</field>
    <description>HONEYTOKEN COMPROMETIDO: $(honeytokens) leido por $(src_ip) via '$(command)'</description>
    <mitre><id>T1552</id></mitre>
  </rule>

  <!-- Sesion con actividad sostenida: atacante interactivo, no escaner -->
  <rule id="100220" level="13" frequency="10" timeframe="300">
    <if_matched_sid>100210</if_matched_sid>
    <same_field>session_id</same_field>
    <description>CIBERENGANO: sesion interactiva sostenida desde $(src_ip) - operador humano probable</description>
  </rule>

  <!-- Alertas operativas: el senuelo puede haberse vuelto detectable -->
  <rule id="100230" level="8">
    <if_sid>100200</if_sid>
    <field name="event_type">system.inference_degraded</field>
    <description>OPERACION: motor de inferencia caido, senuelo en modo degradado</description>
  </rule>

  <rule id="100231" level="7">
    <if_sid>100200</if_sid>
    <field name="event_type">system.latency_breach</field>
    <description>OPERACION: latencia de $(latency_ms) ms sobre el objetivo - riesgo de fingerprinting</description>
  </rule>

</group>
```

Validar antes de aplicar:
```bash
sudo /var/ossec/bin/wazuh-logtest
# pegar una linea de deception-events.jsonl
```

### Exclusión de escaneo autorizado

El escáner de vulnerabilidades corporativo y el inventario de red generarán `session.opened`. Son conexiones reales, pero no intrusiones. Excluirlas por IP de origen —esta es la condición de contorno de la afirmación de cero falsos positivos, y conviene documentarla explícitamente en la memoria:

```xml
  <rule id="100290" level="0">
    <if_sid>100201</if_sid>
    <field name="src_ip">^10\.42\.0\.(10|11)$</field>
    <description>Escaneo autorizado del inventario: descartado</description>
  </rule>
```

---

## 5. Alternativa: Filebeat → Elasticsearch

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /ruta/al/repo/data/logs/deception-events.jsonl
    json.keys_under_root: true
    json.add_error_key: true
    fields:
      product: generative-deception-framework
    fields_under_root: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "deception-%{+yyyy.MM.dd}"

setup.template.name: "deception"
setup.template.pattern: "deception-*"
```

Consultas útiles en Kibana:

```
event_type: "command.executed" and severity: "critical"
honeytokens: *
event_type: "session.closed" and max_severity >= 8
```

---

## 6. Uso de los Honeytokens Fuera del Señuelo

Es donde los honeytokens aportan su valor real. Las credenciales fabricadas por el Agente de Artefactos no autentican contra nada, así que **su aparición en cualquier punto del parque es un verdadero positivo por construcción**.

Obtener la lista tras el despliegue:

```bash
curl -s http://127.0.0.1:8000/stats | python -m json.tool
docker compose exec deception-agent cat /app/data/persona.json
```

Registrarlas como indicadores en:

* Logs de autenticación de la base de datos real (uso de la contraseña de BD del señuelo).
* Pasarela de correo (uso de la contraseña SMTP).
* Logs de la pasarela de API (uso de la clave de API).
* Autenticación SSH del parque (uso de la clave privada).

Una regla que dispare ante cualquiera de estos es de máxima confianza: no existe camino legítimo por el que esa credencial llegue a usarse.

---

## 7. Pendiente de Validación

Para cerrar esta fase con resultados y no con especificación:

1. Desplegar un Wazuh manager + agente (contenedor o VM).
2. Aplicar las reglas y validarlas con `wazuh-logtest` sobre eventos reales del señuelo.
3. Ejecutar una sesión de reconocimiento completa y capturar el panel de alertas.
4. Medir el retardo entre la ejecución del comando y la aparición de la alerta.
5. Comprobar la regla de correlación 100220 con una sesión de más de 10 comandos.

El punto 4 —tiempo hasta la alerta— es la métrica que conecta esta fase con el argumento de MTTR del capítulo 1, y merece medirse.
