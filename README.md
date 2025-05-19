# wHash
Un script simple en Python que detecta el tipo de hash (MD5, SHA-1, SHA-256, SHA-512, bcrypt, Argon2, PBKDF2, SHA-256crypt, SHA-512crypt) y lo compara contra un diccionario (opcional) para intentar descubrir su valor original.

En caso de aportar un diccionario puede crackear los hashes MD5, SHA-1, SHA-256, SHA-512.

## Uso

1. Clonar el repo
```bash
git clone https://github.com/Delamm/wHash.git
cd wHash
```
2. Ejecutar el script
```python
python3 wHash.py <hash> -d <diccionario(opcional)>
```
Ejemplo:
```shell
❯ python3 wHash.py 482c811da5d5b4bc6d497ffa98491e38 -d /usr/share/wordlists/rockyou.txt

🔍 Hash analizado: 482c811da5d5b4bc6d497ffa98491e38
🛠️ Algoritmos detectados:
 - MD5

🔍 Buscando en diccionario: /usr/share/wordlists/rockyou.txt
¡Coincidencia! Palabra: 'password123' (Algoritmo: MD5)
```
