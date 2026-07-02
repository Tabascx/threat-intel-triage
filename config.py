import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")


def verificar_claves() -> None:
    """Avisa si falta alguna clave antes de intentar consultar las APIs."""
    faltantes = []
    if not VIRUSTOTAL_API_KEY:
        faltantes.append("VIRUSTOTAL_API_KEY")
    if not ABUSEIPDB_API_KEY:
        faltantes.append("ABUSEIPDB_API_KEY")
    if not OTX_API_KEY:
        faltantes.append("OTX_API_KEY")

    if faltantes:
        raise EnvironmentError(
            f"Faltan claves en el archivo .env: {', '.join(faltantes)}"
        )
