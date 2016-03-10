import base64
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto import Random

import json

KEY_LENGTH = 16
CHIPER = AES
CHIPER_MODE = AES.MODE_CBC
HASH_FUNC = sha256


def to_str(value):
    """
    Ensure value has str type
    :param value: string to check
    :type value: str or bytes
    :return: str value
    """
    if isinstance(value, bytes):
        value = value.decode()
    return value


def to_bytes(value, check_length=False):
    """
    Ensure value has bytes type
    :param value: string to check
    :type value: str or bytes
    :return: bytes value
    """
    if isinstance(value, str):
        value = value.encode()
    return value


def b64decode(encoded_string):
    """
    Decode from Base64.
    :param encoded_string: string to decode
    :type encoded_string: str
    :return: decoded bytes
    """
    encoded_string = to_bytes(encoded_string)
    string = encoded_string.replace(b' ', b'+')
    return to_bytes(base64.b64decode(string))


def b64encode(string):
    """
    Encode to Base64.
    :param string: string to encode
    :type string: bytes
    :return: encoded string
    """
    string = to_bytes(string)
    return to_str(base64.b64encode(string))


def get_cipher(key, iv=b"\0" * 16):
    """
    Get cipher object
    :param key: cipher key
    :type  key: bytes
    :param iv: cipher initialization vector
    :return: cipher
    """
    return CHIPER.new(key, CHIPER_MODE, iv)


def encrypt(plaintext, key):
    """
    Encrypt given plaintext.
    :param plaintext: b64 encoded text
    :type plaintext: str
    :param key: key (b64 encoded) to use
    :param key: str
    :return: b64 encoded cypher text
    """
    key = b64decode(key)
    key = to_bytes(key)

    plaintext = to_bytes(plaintext)

    if len(plaintext) % 16:
        plaintext += b' ' * (16 - len(plaintext) % 16)

    iv = generate_random()
    enc = get_cipher(key, iv).encrypt(plaintext)

    return b64encode(iv + enc)


def decrypt(ciphertext, key):
    """
    Decrypt ciphertext with given key.
    :param ciphertext: b64 encoded text
    :type ciphertext: str
    :param key: key (b64 encoded) to use
    :return: dectypted text
    """
    key = b64decode(key)
    key = to_bytes(key)

    ciphertext = b64decode(ciphertext)
    ciphertext = to_bytes(ciphertext)

    iv = ciphertext[:KEY_LENGTH]
    ciphertext = ciphertext[KEY_LENGTH:]

    cipher = get_cipher(key, iv)
    decrypted = cipher.decrypt(ciphertext)

    if decrypted[-1] <= KEY_LENGTH:
        decrypted = decrypted[:-decrypted[-1]]

    return decrypted.decode().strip()


def encrypt_json(json_dict, cipher_key):
    """
    Encrypt given dictionary (json).
    :param json_dict: dictionary to encrypt
    :type json_dict: dict
    :param cipher_key: key to use (b64)
    :type cipher_key: str
    :return: encrypted line
    """
    for key, value in json_dict.items():
        json_dict[key] = to_str(value)

    plaintext = json.dumps(json_dict)
    encrypted = encrypt(plaintext, cipher_key)

    return encrypted


def decrypt_json(encrypted_json, cipher_key):
    """
    Decrypt given cyphertext to dictionary (json).
    :param encrypted_json: text to decrypt
    :type encrypted_json: str
    :param cipher_key: key to use (b64)
    :type cipher_key: str
    :return: decrypted dict
    """
    decrypted = decrypt(encrypted_json, cipher_key)
    return json.loads(decrypted)


def generate_random(length=KEY_LENGTH):
    """
    Generates random sequence.
    :param length: num of bytes to generate
    :type length: int
    :return: random sequence
    """
    return Random.new().read(length)


def generate_b64key():
    """
    Generates key and encode (with base 64) key.
    :return: encoded key
    """
    return b64encode(generate_random(KEY_LENGTH))


def compute_hash(string):
    """
    Computes hash from given string.
    :param string: string to hash
    :return: hash string
    """
    string = to_bytes(string)
    return HASH_FUNC(string).digest()


def password2key(password):
    """
    Transform password to key (using hash).
    :param password: password to transform
    :return: b64 encoded key
    """
    return b64encode(compute_hash(password)[:KEY_LENGTH])
