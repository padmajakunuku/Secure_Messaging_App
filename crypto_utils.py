from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

SALT_SIZE = 16
KEY_SIZE = 32
IV_SIZE = 16
ITERATIONS = 100_000

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS)

def encrypt(data: bytes, password: str) -> bytes:
    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data))
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(encrypted)
    mac = hmac.digest()
    return salt + iv + encrypted + mac

def decrypt(enc_data: bytes, password: str) -> bytes:
    salt = enc_data[:SALT_SIZE]
    iv = enc_data[SALT_SIZE:SALT_SIZE + IV_SIZE]
    mac = enc_data[-32:]
    encrypted = enc_data[SALT_SIZE + IV_SIZE:-32]
    key = derive_key(password, salt)
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(encrypted)
    hmac.verify(mac)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted))