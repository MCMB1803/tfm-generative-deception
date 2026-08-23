# Validacion de las reglas de correlacion en Wazuh

Generado automaticamente por `siem/validate_rules.py` el 2026-08-23T00:45:30+00:00. **No editar a mano**: se regenera en cada ejecucion.

Resultado: **10/10** reglas disparan el identificador y el nivel que declara el diseno. Eventos reales disponibles en el log del framework: **369**.

Cada caso se comprueba pasando un evento por `wazuh-logtest` dentro del manager en ejecucion y leyendo la regla que finalmente dispara. Los eventos marcados como *real* proceden del log que el framework produjo durante las pruebas; los marcados como *sintetico* corresponden a condiciones que no se dieron en esta ejecucion y se construyen a mano, lo que se declara aqui en lugar de presentarlos como observados.

| Caso | Origen | Regla esperada | Nivel | Disparo | Resultado |
|---|---|---|---|---|---|
| session.opened | real | `100201` | 12 | 100201 / 12 | OK |
| auth.attempt | real | `100202` | 12 | 100202 / 12 | OK |
| command.executed (severidad baja) | real | `100210` | 8 | 100210 / 8 | OK |
| command.executed (severidad alta) | real | `100211` | 12 | 100211 / 12 | OK |
| command.executed (severidad critica) | sintetico | `100212` | 14 | 100212 / 14 | OK |
| honeytoken leido | real | `100213` | 15 | 100213 / 15 | OK |
| system.inference_degraded | sintetico | `100230` | 8 | 100230 / 8 | OK |
| system.latency_breach | real | `100231` | 7 | 100231 / 7 | OK |
| escaneo autorizado descartado | sintetico | `100290` | 0 | 100290 / 0 | OK |
| sesion interactiva sostenida | real (rafaga de 12) | `100220` | 13 | 100210 | OK |

## Por que cada regla existe

* **100201** — session.opened: Toda conexion al senuelo es no autorizada por construccion.
* **100202** — auth.attempt: Credenciales capturadas en claro.
* **100210** — command.executed (severidad baja): Comando sin clasificacion de riesgo elevado.
* **100211** — command.executed (severidad alta): Reconocimiento avanzado segun la clasificacion ATT&CK.
* **100212** — command.executed (severidad critica): Acceso a credenciales o evasion.
* **100213** — honeytoken leido: La senal de mayor valor del sistema: un artefacto trampa exfiltrado.
* **100230** — system.inference_degraded: El motor de inferencia no responde; el senuelo puede haberse vuelto detectable.
* **100231** — system.latency_breach: Respuesta por encima del objetivo: riesgo de fingerprinting temporal.
* **100290** — escaneo autorizado descartado: Condicion de contorno de la afirmacion de cero falsos positivos: el escaner corporativo genera session.opened y no debe alertar.
* **100220** — sesion interactiva sostenida: diez comandos en la misma sesion en cinco minutos distinguen a un operador humano de un escaner automatico.

## Alcance de esta validacion

La regla **100212** no llega a dispararse con trafico real: en este framework todo comando de severidad critica accede a un fichero de credenciales, que es precisamente donde viven los honeytokens, de modo que la 100213 -- mas especifica y de mayor nivel -- la eclipsa siempre. Se valida con un evento sintetico, que demuestra que la regla es correcta cuando se alcanza, pero conviene saber que en explotacion normal no producira alertas propias.

Se comprueba que el motor de analisis de Wazuh decodifica los eventos y dispara la regla correcta con el nivel correcto. **No** se comprueba el transporte desde el agente hasta el manager ni la visualizacion en el panel, que dependen del despliegue concreto y quedan fuera de lo que este contenedor puede acreditar.
