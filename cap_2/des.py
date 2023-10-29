from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

# Chave de criptografia AES (128 bits)
chave = b"chave12345678901"

# Mensagem para criptografar
mensagem = b"Exemplo de mensagem para criptografia AES."

# Adicionando padding à mensagem
padder = padding.PKCS7(128).padder()
mensagem_pad = padder.update(mensagem) + padder.finalize()

# Criando um objeto de cifra AES em modo CBC
cipher = Cipher(algorithms.AES(chave), modes.CFB(b'\0' * 16), backend=default_backend())

# Criptografando a mensagem
encryptor = cipher.encryptor()
mensagem_cifrada = encryptor.update(mensagem_pad) + encryptor.finalize()

# Convertendo a mensagem cifrada para base64 para fácil visualização
mensagem_cifrada_base64 = base64.b64encode(mensagem_cifrada).decode('utf-8')

print("Mensagem cifrada (em base64):", mensagem_cifrada_base64)

# Descriptografando a mensagem
decryptor = cipher.decryptor()
mensagem_decifrada_pad = decryptor.update(mensagem_cifrada) + decryptor.finalize()

# Removendo o padding da mensagem decifrada
unpadder = padding.PKCS7(128).unpadder()
mensagem_decifrada = unpadder.update(mensagem_decifrada_pad) + unpadder.finalize()

print("Mensagem decifrada:", mensagem_decifrada.decode('utf-8'))
