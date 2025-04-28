from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from eth_hash.auto import keccak

def generate_rsa_keys():
    # Генерує приватний та публічний ключі RSA.
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    #Серіалізує публічний ключ у формат PEM (байти)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem # Повертаємо байти

def serialize_private_key(private_key):
    # Серіалізує приватний ключ у формат PEM (байти).
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # Поки без шифрування, але в реальному використанні
        # дуже бажано шифрувати приватний ключ
    )
    return pem # Повертаємо байти


# Функція для перетворення байтового PEM ключа на об'єкт Python для подальшої взаємодії
def load_private_key_from_pem(pem_bytes: bytes):
    """Завантажує приватний ключ з байтів у форматі PEM."""
    private_key = serialization.load_pem_private_key(
        pem_bytes,
        password=None,
        backend=default_backend()
    )
    return private_key

def load_public_key_from_pem(pem_bytes: bytes):
    """Завантажує публічний ключ з байтів у форматі PEM."""
    public_key = serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )
    return public_key

def hash_data_keccak256(data_bytes: bytes):
    """Хешує байти даних за допомогою Keccak-256."""
    return keccak(data_bytes).hex() # Повертаємо хеш у шістнадцятковому форматі

def sign_data_rsa(private_key, data_to_sign: bytes):
    """Підписує байти даних за допомогою приватного ключа RSA."""
    signature = private_key.sign(
        data_to_sign,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() # Використовуємо SHA-256 для хешування даних перед підписом
    )
    return signature # Повертаємо підпис у байтах

def verify_signature_rsa(public_key, data_to_verify: bytes, signature: bytes):
    """Перевіряє підпис даних за допомогою публічного ключа RSA."""
    try:
        public_key.verify(
            signature,
            data_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256() # Використовуємо SHA-256 для хешування даних перед перевіркою
        )
        return True # Підпис дійсний
    except InvalidSignature:
        return False # Підпис недійсний

# Приклад використання (для тестування):
if __name__ == "__main__":
    # Утворення приватного і публічного ключа
    priv_key, pub_key = generate_rsa_keys()
    pub_pem_bytes = serialize_public_key(pub_key)
    priv_pem_bytes = serialize_private_key(priv_key)

    # Тестування хешування
    # data_to_hash = b"Data to hash"
    # hashed_data = hash_data_keccak256(data_to_hash)
    # print(f"Хеш даних (Keccak-256): {hashed_data}")

    # Тестування підпису та перевірки
    data_to_sign = b"Data to be signed"
    signature = sign_data_rsa(priv_key, data_to_sign)
    print(f"\nПідпис (байти): {signature.hex()}") # Виводимо підпис у шістнадцятковому форматі

    # Завантажую ключі з PEM для тестування
    loaded_priv_key = load_private_key_from_pem(priv_pem_bytes)
    loaded_pub_key = load_public_key_from_pem(pub_pem_bytes)

    # Перевірка дійсного підпису
    is_valid = verify_signature_rsa(loaded_pub_key, data_to_sign, signature)
    print(f"Підпис дійсний? {is_valid}")

    # Перевірка недійсного підпису (змінюємо дані)
    data_to_verify_wrong = b"Fake data"
    is_valid_wrong = verify_signature_rsa(loaded_pub_key, data_to_verify_wrong, signature)
    print(f"Підпис дійсний (з невірними даними)? {is_valid_wrong}")