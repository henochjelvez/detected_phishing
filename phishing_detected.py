import os
import re
import requests
import socket
from email import policy
from email.parser import BytesParser
import shutil

# Configuración de las APIs
VT_API_KEY = "xxx"
HUNTER_API_KEY = "xxx"
DIRECTORIO_OBSERVADO = "."
CARPETA_ANALIZADOS = "analizados"

# Crear directorio para los archivos analizados si no existe
os.makedirs(CARPETA_ANALIZADOS, exist_ok=True)

# Función para limpiar correos electrónicos y extraer solo el email válido
def limpiar_email(email):
    email_regex = r'<(.*?)>'
    match = re.search(email_regex, email)
    if match:
        return match.group(1).strip()
    return email.strip()

# Función para validar correos electrónicos usando Hunter.io
def validar_email_hunter(email):
    url_hunter = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={HUNTER_API_KEY}"
    try:
        response = requests.get(url_hunter)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return data
        elif response.status_code == 400:
            return {"status": "invalid", "reason": "El correo tiene un formato inválido."}
        else:
            return {"status": "error", "reason": f"Error {response.status_code}: {response.text}"}
    except Exception as e:
        return {"status": "error", "reason": str(e)}

# Función para validar dominio con VirusTotal
def validar_dominio_virustotal(dominio):
    dominio = dominio.strip()  # Elimina caracteres no deseados
    url_vt = f"https://www.virustotal.com/api/v3/domains/{dominio}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url_vt, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            details = []
            vendors = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            for vendor, result in vendors.items():
                if result.get('category') == 'malicious':
                    details.append(f"{vendor}: {result.get('result')}")
            return malicious_count, details
        return 0, []
    except Exception as e:
        return 0, []

# Función para validar IPs con VirusTotal
def validar_ip_virustotal(ip):
    url_vt = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url_vt, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            details = []
            vendors = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            for vendor, result in vendors.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    details.append(f"{vendor}: {result.get('result')}")
            return malicious_count, details
        return 0, []
    except Exception as e:
        return 0, []

# Función para extraer URLs del contenido
def extraer_urls(contenido):
    regex = r'https?://[\w.-/]+'
    return re.findall(regex, contenido)

# Función para extraer dominios de URLs
def extraer_dominios(urls):
    dominios = []
    for url in urls:
        dominio = re.search(r'://([^/]+)', url)
        if dominio:
            dominios.append(dominio.group(1))
    return dominios

# Función para extraer dominios en texto plano
def extraer_dominios_texto(contenido):
    regex = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    return re.findall(regex, contenido)

# Función para resolver IPs de dominios
def resolver_ips_dominio(dominio):
    try:
        return socket.gethostbyname(dominio)
    except socket.gaierror:
        return None

# Función para extraer IPs del contenido
def extraer_ips(contenido):
    regex = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(regex, contenido)

# Función para analizar psicología del correo
def analizar_psicologia(contenido):
    palabras_clave = ["urgente", "hacer clic aquí", "inicie sesión", "actualice su cuenta", "verificar", "premio", "oferta"]
    sospechoso = any(palabra.lower() in contenido.lower() for palabra in palabras_clave)
    if sospechoso:
        return "El contenido tiene indicios de persuasión sospechosa."
    return "El contenido no muestra indicios claros de persuasión sospechosa."

# Función para mover el archivo analizado a la carpeta de analizados
def mover_archivo_analizado(ruta_archivo):
    if not os.path.exists(CARPETA_ANALIZADOS):
        os.makedirs(CARPETA_ANALIZADOS)
    nuevo_nombre = os.path.join(CARPETA_ANALIZADOS, os.path.basename(ruta_archivo))
    shutil.move(ruta_archivo, nuevo_nombre)
    return nuevo_nombre

# Función para analizar el correo
def analizar_correo(ruta_archivo):
    with open(ruta_archivo, 'rb') as f:
        correo = BytesParser(policy=policy.default).parse(f)

    reporte = []
    reporte.append(f"De: {correo['from']}")
    reporte.append(f"Para: {correo['to']}")
    reporte.append(f"Asunto: {correo['subject']}")
    reporte.append(f"Fecha: {correo['date']}")

    # Validar remitente
    de_correo = correo['from']
    if de_correo:
        de_correo_limpio = limpiar_email(de_correo)
        dominio = de_correo_limpio.split('@')[-1]
        validacion_hunter = validar_email_hunter(de_correo_limpio)
        if isinstance(validacion_hunter, dict):
            reporte.append(f"Correo remitente limpio: {de_correo_limpio}")
            reporte.append(f"Estado del correo según Hunter.io: {validacion_hunter.get('status', 'unknown')}")
            reporte.append(f"Razón: {validacion_hunter.get('reason', 'No especificada.')}")

            # Validar dominio con VirusTotal
            malicious_count, details = validar_dominio_virustotal(dominio)
            if malicious_count > 0:
                reporte.append(f"Dominio {dominio}: Sospechoso ({malicious_count} detecciones)")
                for detail in details:
                    reporte.append(f"  - {detail}")
            else:
                reporte.append(f"Dominio {dominio}: Confiable")
        else:
            reporte.append("Error al validar el correo con Hunter.io.")
    else:
        reporte.append("Correo remitente no especificado.")

    # Extraer y analizar URLs
    contenido = correo.get_body(preferencelist=('plain', 'html')).get_content()
    urls = extraer_urls(contenido)
    reporte.append(f"URLs detectadas: {urls}")
    dominios_urls = extraer_dominios(urls)

    # Extraer dominios en texto
    dominios_texto = extraer_dominios_texto(contenido)
    dominios_totales = set(dominios_urls + dominios_texto)
    reporte.append(f"Dominios detectados: {list(dominios_totales)}")

    for dominio in dominios_totales:
        malicious_count, details = validar_dominio_virustotal(dominio)
        if malicious_count > 0:
            reporte.append(f"- {dominio}: Sospechoso ({malicious_count} detecciones)")
            for detail in details:
                reporte.append(f"  - {detail}")
        else:
            reporte.append(f"- {dominio}: Confiable")
        ip_resuelta = resolver_ips_dominio(dominio)
        if ip_resuelta:
            malicious_count_ip, details_ip = validar_ip_virustotal(ip_resuelta)
            if malicious_count_ip > 0:
                reporte.append(f"  IP asociada {ip_resuelta}: Sospechosa ({malicious_count_ip} detecciones)")
                for detail in details_ip:
                    reporte.append(f"    - {detail}")
            else:
                reporte.append(f"  IP asociada {ip_resuelta}: Confiable")

    # Extraer y analizar IPs del contenido
    ips = extraer_ips(contenido)
    reporte.append(f"IPs detectadas en el contenido: {ips}")
    for ip in ips:
        malicious_count_ip, details_ip = validar_ip_virustotal(ip)
        if malicious_count_ip > 0:
            reporte.append(f"- {ip}: Sospechosa ({malicious_count_ip} detecciones)")
            for detail in details_ip:
                reporte.append(f"    - {detail}")
        else:
            reporte.append(f"- {ip}: Confiable")

    # Analizar psicología del correo
    psicologia = analizar_psicologia(contenido)
    reporte.append(f"Análisis de psicología del correo: {psicologia}")

    # Generar hipótesis
    if validacion_hunter.get('status') not in ["valid", "accept_all"]:
        hipotesis = "Correo inválido (remitente no confiable)."
    elif any(reputacion_ip == "Maliciosa" for ip in ips):
        hipotesis = "Correo sospechoso (IPs maliciosas detectadas)."
    else:
        hipotesis = "Correo válido."

    reporte.append(f"Hipótesis final: {hipotesis}")
    print("\n".join(reporte))  # Mostrar reporte

    # Mover el archivo analizado a la carpeta de analizados
    nueva_ruta = mover_archivo_analizado(ruta_archivo)
    reporte.append(f"Archivo movido a: {nueva_ruta}")

    return reporte, hipotesis

# Función para guardar el reporte
def guardar_reporte_txt(ruta_archivo, reporte):
    nombre_reporte = os.path.splitext(os.path.basename(ruta_archivo))[0] + "_reporte.txt"
    ruta_reporte = os.path.join(CARPETA_ANALIZADOS, nombre_reporte)
    with open(ruta_reporte, 'w') as f:
        f.write("\n".join(reporte))
    return ruta_reporte

# Función principal
def monitorizar_directorio():
    print("Iniciando análisis de correos...")
    archivos = [f for f in os.listdir(DIRECTORIO_OBSERVADO) if f.endswith('.eml')]
    for archivo in archivos:
        ruta_archivo = os.path.join(DIRECTORIO_OBSERVADO, archivo)
        print(f"Analizando {ruta_archivo}...")
        try:
            reporte, hipotesis = analizar_correo(ruta_archivo)
            guardar_reporte_txt(ruta_archivo, reporte)
        except Exception as e:
            print(f"Error procesando {ruta_archivo}: {e}")
    print("Análisis completado.")

if __name__ == "__main__":
    monitorizar_directorio()
