#!/usr/bin/env python3

import re
import sys
import hashlib
import argparse
import base64
import binascii

def detect_hash_type(hash_input):
    hash_input = hash_input.strip();
    hash_type = [];

    hex_regex = re.compile(r'^[a-f0-9]+$', re.IGNORECASE);
    base64_regex = re.compile(
        r'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    );

    # Detección por prefijos (bcrypt, Argon2, etc.)
    if hash_input.startswith(("$2a$", "$2b$", "$2y$")):
        hash_type.append("bcrypt");
    elif hash_input.startswith("$argon2"):
        hash_type.append("Argon2");
    elif hash_input.startswith("$pbkdf2"):
        hash_type.append("PBKDF2");
    elif hash_input.startswith("$5$"):
        hash_type.append("SHA-256crypt");
    elif hash_input.startswith("$6$"):
        hash_type.append("SHA-512crypt");

    # Detección por formato hexadecimal (MD5, SHA-1, etc.)
    elif hex_regex.fullmatch(hash_input):
        length = len(hash_input);
        if length == 32:
            hash_type.append("MD5");
        elif length == 40:
            hash_type.append("SHA-1");
        elif length == 64:
            hash_type.append("SHA-256");
        elif length == 128:
            hash_type.append("SHA-512");

    # Validación de Base64 (solo si no es hexadecimal)
    else:
        if base64_regex.fullmatch(hash_input):
            try:
                decoded_bytes = base64.b64decode(hash_input, validate=True);
                decoded_hex = decoded_bytes.hex();

                # Caso 1: Contenido es un hash hexadecimal codificado en Base64
                if re.fullmatch(r'^[a-f0-9]+$', decoded_hex, re.IGNORECASE):
                    hex_length = len(decoded_hex);
                    if hex_length == 32:
                        hash_type.append("Base64(MD5)");
                    elif hex_length == 40:
                        hash_type.append("Base64(SHA-1)");
                    elif hex_length == 64:
                        hash_type.append("Base64(SHA-256)");
                    elif hex_length == 128:
                        hash_type.append("Base64(SHA-512)");

                # Caso 2: Contenido es un hash binario (MD5, SHA-1, etc.)
                elif len(decoded_bytes) in [16, 20, 32, 64]:
                    algo = {
                        16: "MD5",
                        20: "SHA-1",
                        32: "SHA-256",
                        64: "SHA-512"
                    }[len(decoded_bytes)]
                    hash_type.append(f"Base64({algo})");

            except (binascii.Error, ValueError):
                pass;  # Si falla la decodificación, no se agrega nada

    return hash_type if hash_type else ["Algoritmo desconocido"];

def generate_hash(word, algorithm):
    
   # Genera el hash de una palabra usando el algoritmo especificado
    
    word_bytes= word.encode("utf-8");
    algorithm= algorithm.lower();

    if algorithm == "md5":
        return hashlib.md5(word_bytes).hexdigest();
    elif algorithm == "sha-1":
        return hashlib.sha1(word_bytes).hexdigest();
    elif algorithm == "sha-256":
        return hashlib.sha256(word_bytes).hexdigest();
    elif algorithm == "sha-512":
        return hashlib.sha512(word_bytes).hexdigest();
    else:
        raise ValueError(f"Algoritmo no soportado: {algorithm}");

def check_dictionary(hash_input, dict_path, algorithms):
    # Compara el hash con palabras de un diccionario
    try:
        with open(dict_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                word = line.strip()
                for algo in algorithms:
                    if algo.lower() in ["md5", "sha-1", "sha-256", "sha-512"]:
                        generated_hash= generate_hash(word, algo);
                        if generated_hash.lower() == hash_input.lower():
                            print(f"\033[92m¡Coincidencia!\033[0m Palabra: '{word}' (Algoritmo: {algo})");
                            return True;

        return False

    except FileNotFoundError:
        print(f"\033[91mError:\033[0m Archivo '{dict_path}' no encontrado.");
        sys.exit(1);
            

def main():
    parser= argparse.ArgumentParser(description="Identificador avanzado de hashes con soporte para diccionarios.");
    parser.add_argument("hash", help="Hash a analizar");
    parser.add_argument("-d", "--dict", help="Ruta al archivo de diccinario");
    args = parser.parse_args();

    hash_input= args.hash.strip();
    algorithms= detect_hash_type(hash_input);

    print(f"\n\033[1m🔍 Hash analizado:\033[0m {hash_input}");
    print("\033[1m🛠️ Algoritmos detectados:\033[0m");
    
    for algo in algorithms:
        print(f" - {algo}");

    if args.dict:
        print(f"\n\033[1m🔍 Buscando en diccionario:\033[0m {args.dict}");
        if not check_dictionary(hash_input, args.dict, algorithms):
            print("\033[93m🚫 No se encontraron coincidencias.\033[0m");

if __name__ == "__main__":
    main();
