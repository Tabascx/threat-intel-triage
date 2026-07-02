from analizar import calcular_veredicto


def test_veredicto_alto_riesgo_con_dos_senales():
    informe = {
        "virustotal": {"maliciosos": 16, "total_motores": 91},
        "abuseipdb": {"score_confianza_abuso": 100, "total_reportes": 135},
        "otx": {"num_pulsos": 0, "pulsos_relacionados": []},
    }
    assert calcular_veredicto(informe) == "ALTO RIESGO"


def test_veredicto_riesgo_moderado_con_una_senal():
    informe = {
        "virustotal": {"maliciosos": 0, "total_motores": 91},
        "abuseipdb": {"score_confianza_abuso": 75, "total_reportes": 10},
        "otx": {"num_pulsos": 0, "pulsos_relacionados": []},
    }
    assert calcular_veredicto(informe) == "RIESGO MODERADO"


def test_veredicto_sin_senales_ip_limpia():
    informe = {
        "virustotal": {"maliciosos": 0, "total_motores": 91},
        "abuseipdb": {"score_confianza_abuso": 0, "total_reportes": 0},
        "otx": {"num_pulsos": 0, "pulsos_relacionados": []},
    }
    assert calcular_veredicto(informe) == "SIN SEÑALES DE RIESGO"


def test_veredicto_ignora_ruido_bajo():
    """Un solo motor de 91 marcando malicioso es ruido normal,
    no debe disparar ninguna senal por si solo."""
    informe = {
        "virustotal": {"maliciosos": 1, "total_motores": 91},
        "abuseipdb": {"score_confianza_abuso": 0, "total_reportes": 118},
        "otx": {"num_pulsos": 0, "pulsos_relacionados": []},
    }
    assert calcular_veredicto(informe) == "SIN SEÑALES DE RIESGO"


def test_veredicto_maneja_fuente_con_error():
    """Si una fuente fallo (por ejemplo timeout), el veredicto debe
    seguir calculandose con las fuentes que si respondieron."""
    informe = {
        "virustotal": {"maliciosos": 16, "total_motores": 91},
        "abuseipdb": {"score_confianza_abuso": 100, "total_reportes": 135},
        "otx": {"error": "Error de conexion: timeout"},
    }
    assert calcular_veredicto(informe) == "ALTO RIESGO"


def test_veredicto_alto_riesgo_por_pulsos_otx():
    informe = {
        "virustotal": {"maliciosos": 0, "total_motores": 91},
        "abuseipdb": {"score_confianza_abuso": 60, "total_reportes": 5},
        "otx": {"num_pulsos": 3, "pulsos_relacionados": ["Botnet XYZ"]},
    }
    assert calcular_veredicto(informe) == "ALTO RIESGO"
