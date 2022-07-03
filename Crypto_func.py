import hashlib
import random

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA


# key = b'Sixteen byte key'  # Passphrase use to create key
# cipher = AES.new(key, AES.MODE_EAX)
# nonce = cipher.nonce
# ciphertext, tag = cipher.encrypt_and_digest(b'abcddd')
# print(cipher, '\n', key, '\n', nonce, '\n')
# print('ciphertext :', ciphertext)
#
# cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
# plaintext = cipher.decrypt(ciphertext)
# print('plaintext :', plaintext)
alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def hash_256(string):
    salt = 'hcmus'
    return hashlib.sha256(string.encode('utf-8') + salt.encode('utf-8')).hexdigest()


def aes_ksession():
    key_session = str.encode(''.join(random.choice(alphabet) for i in range(16)))  # Passphrase use to create key

    if len(key_session) < 16:
        padding = '%0'  # Padding if key < 16 length
        length = 16

        key_session = key_session.rjust(length, padding)  # Padding key

    cipher = AES.new(key_session, AES.MODE_EAX)  # AES.new('key', 'AES mode', Vector IV)
    nonce = cipher.nonce
    return key_session, nonce


def aes_enc_file(key, file_byte):
    cipher = AES.new(key, AES.MODE_EAX)
    file_e, tag = cipher.encrypt_and_digest(file_byte)
    return file_e


def aes_enc_prikey(passphrase, Kprivate):
    key = str.encode(passphrase)  # Passphrase use to create key

    if len(key) < 16:
        padding = '%0'  # Padding if key < 16 length
        length = 16

        key = key.rjust(length, padding)  # Padding key

    cipher = AES.new(key, AES.MODE_EAX)  # AES.new('key', 'AES mode', Vector IV)
    nonce = cipher.nonce

    # Encrypt start . Kprivate must be bytes type
    Kprivate_enc_ed, tag = cipher.encrypt_and_digest(Kprivate)  # or cipher.encrypt('mess') 'mess' must be string type
    return Kprivate_enc_ed, nonce


def aes_dec(ciphertext, key, nonce):  # Decryption , ciphertext must be bytes type
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    #  Can sua theo UI
    return plaintext


def rsa_keygen():  # Random keygen
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # serialization.BestAvailableEncryption(b'mypassword')
    )

    # Write public key to file
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_public_key.decode('utf-8'), pem_private_key.decode('utf-8')


# RSA Key loading
# from cryptography.hazmat.primitives import serialization
#
# with open("path/to/key.pem", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#     )

def hash_sign(data):
    return SHA256.new(data).digest()


def gnsignature(hash_, key):
    return key.sign(hash_, '')


def verify_signature(hash, public_key, signature):
    return public_key.verify(hash, signature)


def sign():
    with open("sign.txt", "rb") as signedfile:
        s = hash_sign(signedfile.read())

    with open("Private_key.txt", "r") as keyfile:
        private_key = RSA.importKey(keyfile.read().split("\n\n")[0].strip())

    return gnsignature(hash_sign, private_key)[0]


def verify():
    with open("sign.txt", "rb") as signedfile:
        s = hash_sign(signedfile.read())

    with open("Public_key.txt", "r") as keyfile:
        public_key = RSA.importKey(keyfile.read().split("\n\n")[0].strip())

    with open("signaturefile.txt", "r") as signaturefile:
        signature = long(signaturefile.read())

    if verify_signature(hash, public_key, (signature,)):
        return sys.exit("valid signature ")
    else:
        return sys.exit("invalid signature!")


# Encrypt
# data = 'abc'.encode('utf-8')
#
# key = b'Sixteen byte key'
# cipher = AES.new(key, AES.MODE_EAX)
#
# nonce = cipher.nonce
# print("Nonce is : ", nonce)
# ciphertext, tag = cipher.encrypt_and_digest(data)
# print("Ciphertext is : ", ciphertext)
#
# # Decrypt
# cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
# plaintext = cipher.decrypt(ciphertext)
# print('Plaintext is : ', plaintext)
#
# try:
#     cipher.verify(tag)
#     print("The message is authentic:", plaintext)
# except ValueError:
#     print("Key incorrect or message corrupted")