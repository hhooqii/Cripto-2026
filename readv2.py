import sys
from scapy.all import rdpcap, ICMP, Raw

VERDE = "\033[92m"
RESET = "\033[0m"

def descifrar_cesar(texto: str, corrimiento: int) -> str:
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            resultado += chr((ord(char) - base - corrimiento) % 26 + base)
        else:
            resultado += char
    return resultado

def puntaje_espanol(texto: str) -> float:
    frecuencias = "eaosrnidlctupmbgyqhfzvjxkw"
    texto_limpio = texto.lower().replace(" ", "")
    if not texto_limpio:
        return float('inf')

    score = sum(
        frecuencias.index(c) if c in frecuencias else 25
        for c in texto_limpio
    )
    return score / len(texto_limpio) 


def extraer_mensaje_icmp(pcap_file: str) -> str:
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
        if pkt[ICMP].type != 8:   
            continue
        if not pkt.haslayer(Raw):
            continue

        data = pkt[Raw].load
        if len(data) > 8:           
            char_byte = data[8]         
            char = chr(char_byte)
            if char.isprintable():
                mensaje += char
                count   += 1

    print(f"[*] Paquetes ICMP Echo Request encontrados : {count}")
    return mensaje

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Uso: sudo python3 {sys.argv[0]} captura.pcapng")
        sys.exit(1)

    pcap_file = sys.argv[1]

    mensaje_cifrado = extraer_mensaje_icmp(pcap_file)
    print(f"[*] Mensaje cifrado extraído               : {mensaje_cifrado}\n")

    resultados = []
    for corrimiento in range(26):
        descifrado = descifrar_cesar(mensaje_cifrado, corrimiento)
        score      = puntaje_espanol(descifrado)
        resultados.append((corrimiento, descifrado, score))

    mejor_corrimiento = min(resultados, key=lambda x: x[2])[0]

    for corrimiento, descifrado, _ in resultados:
        linea = f"{corrimiento:<4}{descifrado}"
        if corrimiento == mejor_corrimiento:
            print(f"{VERDE}{linea}{RESET}")
        else:
            print(linea)