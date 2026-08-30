#!/usr/bin/env python3
"""
Actividad 3 - MitM: Extrae el mensaje oculto en paquetes ICMP y
prueba los 26 corrimientos del cifrado César. Marca en verde el más probable.

Uso: sudo python3 readv2.py captura.pcapng
Ejemplo: sudo python3 readv2.py cesar.pcapng

Requiere: pip install scapy
"""
import sys
from scapy.all import rdpcap, ICMP, Raw

# ── Colores ANSI ──────────────────────────────
VERDE = "\033[92m"
RESET = "\033[0m"


# ── Descifrado César ──────────────────────────
def descifrar_cesar(texto: str, corrimiento: int) -> str:
    """Invierte el cifrado César aplicando el corrimiento negativo."""
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            resultado += chr((ord(char) - base - corrimiento) % 26 + base)
        else:
            resultado += char
    return resultado


# ── Heurística de idioma ──────────────────────
def puntaje_espanol(texto: str) -> float:
    """
    Calcula qué tan parecido es el texto al español.
    Usa la frecuencia relativa de letras en español.
    Menor puntaje = más probable que sea texto en claro.
    """
    # Frecuencias de letras en español (de mayor a menor)
    frecuencias = "eaosrnidlctupmbgyqhfzvjxkw"
    texto_limpio = texto.lower().replace(" ", "")
    if not texto_limpio:
        return float('inf')

    # Score: suma de la posición de cada letra en el ranking (menor = más frecuente)
    score = sum(
        frecuencias.index(c) if c in frecuencias else 25
        for c in texto_limpio
    )
    return score / len(texto_limpio)  # Normalizado por largo


# ── Extracción de datos ICMP ──────────────────
def extraer_mensaje_icmp(pcap_file: str) -> str:
    """
    Lee el archivo pcap/pcapng y extrae un carácter por paquete ICMP Echo Request.
    El carácter se encuentra en el byte índice 8 del campo data
    (justo después del timestamp de 8 bytes que pone pingv4.py).
    """
    try:
        paquetes = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Archivo no encontrado: {pcap_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error leyendo {pcap_file}: {e}")
        sys.exit(1)

    mensaje = ""
    count   = 0

    for pkt in paquetes:
        if not pkt.haslayer(ICMP):
            continue
        if pkt[ICMP].type != 8:          # Solo Echo Request
            continue
        if not pkt.haslayer(Raw):
            continue

        data = pkt[Raw].load
        if len(data) > 8:                # Necesitamos al menos 9 bytes
            char_byte = data[8]          # Posición 8: nuestro carácter oculto
            char = chr(char_byte)
            if char.isprintable():
                mensaje += char
                count   += 1

    print(f"[*] Paquetes ICMP Echo Request encontrados : {count}")
    return mensaje


# ── Main ──────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} captura.pcapng")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # 1. Extraer mensaje cifrado
    mensaje_cifrado = extraer_mensaje_icmp(pcap_file)
    print(f"[*] Mensaje cifrado extraído               : {mensaje_cifrado}\n")

    # 2. Calcular puntaje para cada corrimiento
    resultados = []
    for corrimiento in range(26):
        descifrado = descifrar_cesar(mensaje_cifrado, corrimiento)
        score      = puntaje_espanol(descifrado)
        resultados.append((corrimiento, descifrado, score))

    # 3. Identificar el más probable (menor score)
    mejor_corrimiento = min(resultados, key=lambda x: x[2])[0]

    # 4. Imprimir tabla completa, verde = más probable
    for corrimiento, descifrado, _ in resultados:
        linea = f"{corrimiento:<4}{descifrado}"
        if corrimiento == mejor_corrimiento:
            print(f"{VERDE}{linea}{RESET}")
        else:
            print(linea)