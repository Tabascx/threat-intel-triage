import sys
import json
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY, verificar_claves
from virustotal_client import consultar_virustotal
from abuseipdb_client import consultar_abuseipdb
from otx_client import consultar_otx

console = Console()


def analizar_ip(ip: str) -> dict:
    """Consulta las tres fuentes y devuelve un informe combinado."""
    console.print(f"\n[bold cyan]Analizando {ip}...[/bold cyan]\n")

    resultado_vt = consultar_virustotal(ip, VIRUSTOTAL_API_KEY)
    resultado_abuse = consultar_abuseipdb(ip, ABUSEIPDB_API_KEY)
    resultado_otx = consultar_otx(ip, OTX_API_KEY)

    informe = {
        "ip": ip,
        "fecha_analisis": datetime.now().isoformat(),
        "virustotal": resultado_vt,
        "abuseipdb": resultado_abuse,
        "otx": resultado_otx,
    }

    return informe


def calcular_veredicto(informe: dict) -> str:
    """Combina las senales de las 3 fuentes en un veredicto simple."""
    vt = informe["virustotal"]
    abuse = informe["abuseipdb"]
    otx = informe["otx"]

    señales_maliciosas = 0

    if "error" not in vt and vt.get("maliciosos", 0) > 3:
        señales_maliciosas += 1
    if "error" not in abuse and abuse.get("score_confianza_abuso", 0) > 50:
        señales_maliciosas += 1
    if "error" not in otx and otx.get("num_pulsos", 0) > 0:
        señales_maliciosas += 1

    if señales_maliciosas >= 2:
        return "ALTO RIESGO"
    elif señales_maliciosas == 1:
        return "RIESGO MODERADO"
    else:
        return "SIN SEÑALES DE RIESGO"


def mostrar_informe(informe: dict) -> None:
    """Imprime el informe en consola con formato rich."""
    veredicto = calcular_veredicto(informe)

    color_veredicto = {
        "ALTO RIESGO": "bold red",
        "RIESGO MODERADO": "bold yellow",
        "SIN SEÑALES DE RIESGO": "bold green",
    }[veredicto]

    console.print(Panel(
        f"[{color_veredicto}]{veredicto}[/{color_veredicto}]",
        title=f"Veredicto para {informe['ip']}",
        expand=False,
    ))

    tabla = Table(show_header=True, header_style="bold magenta")
    tabla.add_column("Fuente")
    tabla.add_column("Pais")
    tabla.add_column("Detalle")

    vt = informe["virustotal"]
    if "error" in vt:
        tabla.add_row("VirusTotal", "-", f"[red]{vt['error']}[/red]")
    else:
        tabla.add_row(
            "VirusTotal",
            vt["pais"],
            f"{vt['maliciosos']}/{vt['total_motores']} motores lo marcan malicioso",
        )

    abuse = informe["abuseipdb"]
    if "error" in abuse:
        tabla.add_row("AbuseIPDB", "-", f"[red]{abuse['error']}[/red]")
    else:
        tabla.add_row(
            "AbuseIPDB",
            abuse["pais"],
            f"Score de abuso: {abuse['score_confianza_abuso']}/100 ({abuse['total_reportes']} reportes)",
        )

    otx = informe["otx"]
    if "error" in otx:
        tabla.add_row("AlienVault OTX", "-", f"[red]{otx['error']}[/red]")
    else:
        pulsos_texto = ", ".join(otx["pulsos_relacionados"]) if otx["pulsos_relacionados"] else "Ninguno"
        tabla.add_row(
            "AlienVault OTX",
            otx["pais"],
            f"{otx['num_pulsos']} pulsos de amenaza. Relacionados: {pulsos_texto}",
        )

    console.print(tabla)


def guardar_informe(informe: dict) -> str:
    """Guarda el informe completo en JSON dentro de informes/."""
    Path("informes").mkdir(exist_ok=True)
    nombre_archivo = f"informes/{informe['ip']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(nombre_archivo, "w", encoding="utf-8") as f:
        json.dump(informe, f, indent=2, ensure_ascii=False)

    return nombre_archivo


def main():
    if len(sys.argv) != 2:
        console.print("[red]Uso: python analizar.py <direccion_ip>[/red]")
        sys.exit(1)

    ip = sys.argv[1]

    try:
        verificar_claves()
    except EnvironmentError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    informe = analizar_ip(ip)
    mostrar_informe(informe)
    ruta = guardar_informe(informe)
    console.print(f"\n[dim]Informe guardado en: {ruta}[/dim]\n")


if __name__ == "__main__":
    main()
