import requests

BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def consultar_virustotal(ip: str, api_key: str) -> dict:
    """Consulta la reputacion de una IP en VirusTotal.
    Devuelve un dict con los datos relevantes, o un dict con 'error' si falla."""
    headers = {"x-apikey": api_key}

    try:
        respuesta = requests.get(f"{BASE_URL}/{ip}", headers=headers, timeout=10)
        respuesta.raise_for_status()
        datos = respuesta.json()

        stats = datos["data"]["attributes"]["last_analysis_stats"]
        pais = datos["data"]["attributes"].get("country", "Desconocido")

        return {
            "fuente": "VirusTotal",
            "pais": pais,
            "maliciosos": stats.get("malicious", 0),
            "sospechosos": stats.get("suspicious", 0),
            "inofensivos": stats.get("harmless", 0),
            "total_motores": sum(stats.values()),
        }

    except requests.exceptions.HTTPError as e:
        return {"fuente": "VirusTotal", "error": f"Error HTTP: {e}"}
    except requests.exceptions.RequestException as e:
        return {"fuente": "VirusTotal", "error": f"Error de conexion: {e}"}
    except (KeyError, ValueError) as e:
        return {"fuente": "VirusTotal", "error": f"Respuesta inesperada: {e}"}
