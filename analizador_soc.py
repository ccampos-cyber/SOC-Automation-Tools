import os

# Nombre del archivo de logs que vamos a inspeccionar en el disco duro
ARCHIVO_LOGS = "accesos.log"
lista_negra_ips = {"198.51.100.12"}
UMBRAL_ALERTA = 3
conteo_fallas = {}

print("==================================================")
print("     MONITOR SOC: ANALIZADOR DE ARCHIVOS v3.0    ")
print("==================================================\n")

# Verificamos si el archivo realmente existe en la carpeta antes de abrirlo
if not os.path.exists(ARCHIVO_LOGS):
    print(f"❌ Error: El archivo {ARCHIVO_LOGS} no fue encontrado.")
    exit()

# FUNCIÓN CRÍTICA: Abrimos y procesamos el archivo real línea por línea
with open(ARCHIVO_LOGS, "r") as archivo:
    for linea in archivo:
        # Analizamos la línea solo si contiene el patrón de fallo
        if "Failed password" in linea:
            partes = linea.split("IP: ")
            sub_parte = partes[1]
            ip = sub_parte.split(" - ")[0]
            
            # Control prioritario por Lista Negra (Threat Intelligence)
            if ip in lista_negra_ips:
                print(f"🚨 [ALERTA CRÍTICA - THREAT INTEL] IP Maliciosa Detectada: [{ip}]")
                print(f"-> Acción: Alerta enviada al SIEM para bloqueo inmediato.")
                print("--------------------------------------------------")
            
            # Registro en el diccionario para conteo de fuerza bruta
            if ip in conteo_fallas:
                conteo_fallas[ip] += 1
            else:
                conteo_fallas[ip] = 1

print("\n--- RESUMEN DE PROCESAMIENTO DE ARCHIVO ---")
for ip, fallas in conteo_fallas.items():
    if ip in lista_negra_ips:
        continue
    if fallas >= UMBRAL_ALERTA:
        print(f"🚨 [ALERTA - FUERZA BRUTA] La IP {ip} superó el umbral con {fallas} intentos.")
    else:
        print(f"ℹ️ [Info] IP analizada: {ip} ({fallas} fallos registrados).")
