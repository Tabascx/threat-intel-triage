import requests

BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"


def consultar_otx(ip: str, api_key: str) -> dict:
    """Consulta pulsos de amenazas asociados a una IP en AlienVault OTX.
    Devuelve un dict con los datos relevantes, o un dict con 'error' si falla."""
    headers = {"X-OTX-API-KEY": api_key}

    try:
        respuesta = requests.get(f"{BASE_URL}/{ip}/general", headers=headers, timeout=10)
        respuesta.raise_for_status()
        datos = respuesta.json()

        pulsos = datos.get("pulse_info", {}).get("pulses", [])
        nombres_pulsos = [p.get("name", "Sin nombre") for p in pulsos[:5]]

        return {
            "fuente": "AlienVault OTX",
            "pais": datos.get("country_name", "Desconocido"),
            "num_pulsos": len(pulsos),
            "pulsos_relacionados": nombres_pulsos,
            "reputacion": datos.get("reputation", 0),
        }

    except requests.exceptions.HTTPError as e:
        return {"fuente": "AlienVault OTX", "error": f"Error HTTP: {e}"}
    except requests.exceptions.RequestException as e:
        return {"fuente": "AlienVault OTX", "error": f"Error de conexion: {e}"}
    except (KeyError, ValueError) as e:
        return {"fuente": "AlienVault OTX", "error": f"Respuesta inesperada: {e}"}
