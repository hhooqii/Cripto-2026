import sys


def cifrar_cesar(texto: str, corrimiento: int) -> str:
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            nuevo_char = chr((ord(char) - base + corrimiento) % 26 + base)
            resultado += nuevo_char
        else:
            resultado += char 
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