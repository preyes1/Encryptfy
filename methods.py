from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Used repeat_key initialy before implementing KDF
"""
# Ensures key is 16 bytes
def repeat_key(s):
    return (s * (16 // len(s) + 1))[:16]
"""

def derive_key(password: str, salt: bytes, iterations = 100000):
            password_bytes = password.encode()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                             length=32, salt=salt,
                             iterations = iterations)
            return kdf.derive(password_bytes)