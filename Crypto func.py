import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def hash_256(string):
    hashed_string = hashlib.sha256(string.encode('utf-8')).hexdigest()
    return hashed_string


# def aes_enc(passphase, Kprivate):


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