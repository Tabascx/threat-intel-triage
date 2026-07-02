# Threat Intel Triage

Herramienta de linea de comandos para el triaje rapido de IPs sospechosas. Consulta tres fuentes de inteligencia de amenazas en paralelo (VirusTotal, AbuseIPDB, AlienVault OTX), combina las senales en un veredicto unico y guarda un informe detallado en JSON.

## Por que este proyecto

El primer paso de cualquier investigacion de un indicador de compromiso (IoC) es el triaje: revisar rapidamente si una IP es conocida como maliciosa antes de invertir tiempo en un analisis mas profundo. Hacerlo a mano significa abrir tres pestañas de navegador, copiar la IP tres veces y comparar resultados manualmente. Esta herramienta automatiza ese primer paso y lo reduce a un solo comando.

## Arquitectura

1. Ejecutas `python analizar.py <IP>`
2. El script consulta en paralelo tres fuentes:
   - VirusTotal API
   - AbuseIPDB API
   - AlienVault OTX API
3. Combina los resultados en un veredicto unico: **ALTO RIESGO**, **RIESGO MODERADO** o **SIN SEÑALES DE RIESGO**
4. Muestra una tabla en consola (con `rich`) y guarda un informe completo en JSON dentro de `informes/`

## Funcionalidades

- Consulta simultanea a tres fuentes de reputacion de IPs
- Veredicto combinado que requiere coincidencia entre fuentes, no una sola senal aislada
- Manejo de errores independiente por fuente: si una API falla (timeout, limite de cuota, etc.), las otras dos siguen funcionando y el veredicto se calcula igualmente
- Informe visual en terminal con `rich` (tablas y colores segun nivel de riesgo)
- Guardado automatico de cada analisis en JSON, con marca de tiempo, para consulta posterior

## Stack tecnico

| Componente | Tecnologia |
|---|---|
| Lenguaje | Python 3 |
| Peticiones HTTP | requests |
| Interfaz de consola | rich |
| Configuracion | python-dotenv |
| Tests | pytest |

## Instalacion

### Requisitos
- Python 3.10+
- Claves API gratuitas de VirusTotal, AbuseIPDB y AlienVault OTX

### Pasos

```bash
git clone https://github.com/Tabascx/threat-intel-triage.git
cd threat-intel-triage
python -m venv venv
venv\Scripts\Activate.ps1      # Windows
pip install requests rich python-dotenv pytest
```

Copia `.env.example` a `.env` y rellena tus claves:

```bash
cp .env.example .env
```
VIRUSTOTAL_API_KEY=tu_clave
ABUSEIPDB_API_KEY=tu_clave
OTX_API_KEY=tu_clave

Claves gratuitas disponibles en:
- https://www.virustotal.com/gui/join-us
- https://www.abuseipdb.com/register
- https://otx.alienvault.com/

## Uso

```bash
python analizar.py 8.8.8.8
```

El informe se muestra en terminal y se guarda automaticamente en `informes/<ip>_<fecha>.json`.

## Tests

```bash
pytest -v
```

Los tests cubren la logica de calculo del veredicto de forma aislada (sin llamar a las APIs reales), incluyendo el caso en que una fuente falla y las otras dos deben seguir funcionando.

## Decisiones tecnicas

**Por que combinar tres fuentes en vez de confiar en una sola**: cada servicio tiene sesgos y cobertura distintos. VirusTotal agrega motores antivirus, AbuseIPDB se basa en reportes de la comunidad, y OTX aporta contexto de campanas de amenaza conocidas (pulsos). Correlacionar las tres reduce falsos positivos y falsos negativos frente a depender de una unica fuente.

**Por que el veredicto exige 2 de 3 senales para "alto riesgo"**: un solo motor antivirus marcando una IP como maliciosa de un total de 90+ es ruido estadistico normal, no una senal fiable por si sola (se ve claramente con `8.8.8.8`, que tiene 1 motor en falso positivo pese a ser una IP completamente legitima). Exigir coincidencia entre fuentes evita alertas erroneas.

**Por que cada conector maneja sus propios errores por separado**: en produccion, las APIs externas fallan (timeouts, limites de cuota, mantenimiento). Si una fuente cae, el analisis no debe detenerse por completo: las otras dos siguen aportando senal, y el error se muestra de forma clara en el informe sin romper el flujo.

**Por que las claves API viven en `.env` y no en el codigo**: exponer claves API en el codigo fuente es un riesgo de seguridad basico que cualquier repositorio publico en GitHub puede filtrar accidentalmente. El archivo `.env` real esta excluido via `.gitignore`; solo se versiona `.env.example` como plantilla.
