# 🛡️ SOC Automation Tools: Log Parser & Threat Intel Filter

Este repositorio funciona como mi bitácora técnica de aprendizaje y desarrollo de herramientas automatizadas orientadas a operaciones de seguridad en un *SOC (Security Operations Center)*.

## 📋 Descripción del Proyecto
El script principal analizador_soc.py es una herramienta defensiva desarrollada en Python orientada al análisis automatizado de registros de auditoría (logs). Su objetivo es reducir el tiempo de respuesta ante incidentes mediante dos mecánicas clave:
1. *Detección de Fuerza Bruta:* Monitorea intentos de inicio de sesión fallidos (Failed password) y detona alertas críticas si una dirección IP supera un umbral estático de 3 intentos.
2. *Filtro de Inteligencia de Amenazas (Threat Intelligence):* Implementa un control de acceso prioritario mediante conjuntos (sets), aislando de forma inmediata cualquier IP catalogada en una Lista Negra desde su primer fallo.

## 💻 Tecnologías Utilizadas
* *Lenguaje:* Python 3
* *Entorno de Laboratorio:* Ubuntu Linux (Virtualizado en Oracle VirtualBox)
* *Estructuras de Datos:* Diccionarios para conteo dinámico de eventos y Conjuntos para búsquedas de alta velocidad (O(1)).
