#!/usr/bin/env python3
"""
Name: SSH Brute Force Detector
Author: ccampos
Description: Automatically parses system logs to identify potential 
             brute-force attacks against SSH services.
Target Role: Blue Team / SOC Analyst (Heredia, CR)
"""

import os
import sys

# 1. CONFIGURACIÓN DE RUTAS (Aquí aplicas lo aprendido en Linux)
LOG_FILE = "auth.log"          # Archivo de entrada simulado
REPORT_FILE = "alerts.txt"      # Archivo donde se guardarán las amenazas
FAILED_THRESHOLD = 3            # Número de intentos fallidos para activar la alerta


def check_log_file():
    """Verifica si el archivo de logs existe antes de iniciar."""
    if not os.path.exists(LOG_FILE):
        print(f"[-] Error: Target log file '{LOG_FILE}' not found.")
        print("[*] Please create 'auth.log' in this directory.")
        sys.exit(1)


def parse_logs():
    """Lee el archivo de logs y contabiliza los accesos fallidos por IP."""
    print(f"[*] Starting analysis on {LOG_FILE}...")
    
    # Diccionario para almacenar: { "IP": cantidad_de_fallos }
    failed_attempts = {}

    with open(LOG_FILE, "r") as file:
        for line in file:
            # Buscamos el patrón estándar de un fallo de autenticación
            if "Failed password" in line or "FAILED LOGIN" in line:
                # Lógica para extraer la dirección IP (la programaremos juntos)
                # Por ahora simularemos extraer una IP estática para probar la estructura
                ip_address = extract_ip(line)
                
                if ip_address:
                    failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1

    return failed_attempts


def extract_ip(log_line):
    """Función auxiliar para segmentar la línea y extraer la IP."""
    # Ejemplo simple de segmentación (String splitting)
    # En producción usarás expresiones regulares (Regex)
    words = log_line.split()
    for word in words:
        # Validación rudimentaria de formato IP (contiene puntos)
        if word.count(".") == 3:
            return word
    return None


def generate_alerts(attackers):
    """Escribe los resultados sospechosos en el archivo de reportes."""
    alert_count = 0
    with open(REPORT_FILE, "w") as report:
        report.write("=========================================\n")
        report.write("        SOC BLUE TEAM ALERT REPORT       \n")
        report.write("=========================================\n\n")
        
        for ip, count in attackers.items():
            if count >= FAILED_THRESHOLD:
                alert_count += 1
                msg = f"[CRITICAL] IP {ip} triggered alert: {count} failed login attempts.\n"
                report.write(msg)
                print(msg.strip())
                
    print(f"\n[+] Analysis complete. {alert_count} alerts written to '{REPORT_FILE}'.")


# 2. PUNTO DE ENTRADA PRINCIPAL (Main Execution)
if __name__ == "__main__":
    check_log_file()
    detected_attackers = parse_logs()
    generate_alerts(detected_attackers)

