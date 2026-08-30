#!/usr/bin/env python3
"""
Actividad 1 - Algoritmo de cifrado César
Uso: python3 cesar.py "texto a cifrar" corrimiento
Ejemplo: python3 cesar.py "criptografia y seguridad en redes" 9
"""
import sys


def cifrar_cesar(texto: str, corrimiento: int) -> str:
    """
    Cifra un texto usando el algoritmo César con el corrimiento indicado.
    Los caracteres no alfabéticos (espacios, números, etc.) no se modifican.
    """
    resultado = ""
    for char in texto:
        if char.isalpha():
            # Determinar la base según mayúscula o minúscula
            base = ord('a') if char.islower() else ord('A')
            # Desplazar el carácter y envolver con módulo 26
            nuevo_char = chr((ord(char) - base + corrimiento) % 26 + base)
            resultado += nuevo_char
        else:
            resultado += char  # Espacios y símbolos pasan sin cambio
    return resultado


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Uso: python3 {sys.argv[0]} \"texto a cifrar\" corrimiento")
        print(f"Ejemplo: python3 {sys.argv[0]} \"criptografia y seguridad en redes\" 9")
        sys.exit(1)

    texto_original = sys.argv[1]
    corrimiento = int(sys.argv[2])

    texto_cifrado = cifrar_cesar(texto_original, corrimiento)
    print(texto_cifrado)