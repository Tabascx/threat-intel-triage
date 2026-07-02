import requests

BASE_URL = "https://api.abuseipdb.com/api/v2/check"


def consultar_abuseipdb(ip: str, api_key: str) -> dict:
    """Consulta el score de abuso de una IP en AbuseIPDB.
    Devuelve un dict con los datos relevantes, o un dict con 'error' si falla."""
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        respuesta = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        respuesta.raise_for_status()
        datos = respuesta.json()["data"]

        return {
            "fuente": "AbuseIPDB",
            "pais": datos.get("countryCode", "Desconocido"),
            "score_confianza_abuso": datos.get("abuseConfidenceScore", 0),
            "total_reportes": datos.get("totalReports", 0),
            "isp": datos.get("isp", "Desconocido"),
            "uso": datos.get("usageType", "Desconocido"),
        }

    except requests.exceptions.HTTPError as e:
        return {"fuente": "AbuseIPDB", "error": f"Error HTTP: {e}"}
    except requests.exceptions.RequestException as e:
        return {"fuente": "AbuseIPDB", "error": f"Error de conexion: {e}"}
    except (KeyError, ValueError) as e:
        return {"fuente": "AbuseIPDB", "error": f"Respuesta inesperada: {e}"}
