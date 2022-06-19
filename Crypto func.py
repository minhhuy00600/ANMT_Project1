import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from Crypto.Cipher import AES


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


def hash_256(string):
    hashed_string = hashlib.sha256(string.encode('utf-8')).hexdigest()
    return hashed_string


def aes_enc(passphrase, Kprivate):
    key = str.encode(passphrase)  # Passphrase use to create key

    if len(key) < 16:
        padding = '%0'  # Padding if key < 16 length
        length = 16

        key = key.rjust(length, padding)  # Padding key

    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    # Encrypt start . Kprivate must be bytes type
    Kprivate_enc_ed, tag = cipher.encrypt_and_digest(Kprivate)
    return Kprivate_enc_ed


def aes_dec(ciphertext, key, nonce):  # Decryption , ciphertext must be bytes type
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    #  Can sua theo UI


def rsa_keygen():
    # Write private key
    pri_w = open('PrivateKey.txt', 'w')
    pub_w = open('PubKey.txt', 'w')
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # serialization.BestAvailableEncryption(b'mypassword')
    )

    pri_w.write(pem_private_key.decode('utf-8'))

    # Write public key to file
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    pub_w.write(pem_public_key.decode('utf-8'))

    pri_w.close()
    pub_w.close()


# RSA Key loading
# from cryptography.hazmat.primitives import serialization
#
# with open("path/to/key.pem", "rb") as key_file:
#     private_key = serialization.load_pem_private_key(
#         key_file.read(),
#         password=None,
#     )