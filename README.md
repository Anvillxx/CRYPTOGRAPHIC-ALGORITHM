# CRYPTOGRAPHIC-ALGORITHM
In the provided code we have implemented encryption and decryption of a file using 2 pairs of keys between 2 users by verifying signatures and algorithm which was used consists of RSA and asymmetric Key pairs. Digital signatures were used for verification and hashese were used  to verify the integrity of the file and keys.


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
import os



# Generate keys for User 1
private_key_user1 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key_user1 = private_key_user1.public_key()

# Serialize and save keys for User 1
private_key_user1_pem = private_key_user1.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_user1_pem = public_key_user1.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key_user1.pem', 'wb') as file:
    file.write(private_key_user1_pem)

    with open('public_key_user1.pem', 'wb') as file:
     file.write(public_key_user1_pem)

# Generate keys for User 2
private_key_user2 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048

)
public_key_user2 = private_key_user2.public_key()

# Serialize and save keys for User 2
private_key_user2_pem = private_key_user2.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_user2_pem = public_key_user2.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('private_key_user2.pem', 'wb') as file:
    file.write(private_key_user2_pem)

    with open('public_key_user2.pem', 'wb') as file:
     file.write(public_key_user2_pem)

# Function to compute hash of a file
def hash(file_data):
    hash_func = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_func.update(file_data)
    return hash_func.finalize()

# Simulating User 1 encrypting a text file for User 2
file_name = 'file2encrypt.txt'
encrypted_file = 'encrypted_file.enc'


# Read the text file data
with open('file2encrypt.txt', 'rb') as file:
    plaintext = file.read()

# Hash the file content
pdf_hash = hash(plaintext)
print('HASHED FILE Value:', pdf_hash.hex())


# User 1 encrypts the PDF for User 2 using User 2's public key
cipher = public_key_user2.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the encrypted text-file to a file
with open(encrypted_file, 'wb') as file:
    file.write(cipher)

print("User 1 encrypts the text-file for User 2 using User 2's public key. Encrypted file:", encrypted_file)

# User 1 signs the PDF file with their private key
signature_user1 = private_key_user1.sign(
    plaintext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# User 2 verifies the signature using User 1's public key
try:
    public_key_user1.verify(
        signature_user1,
        plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("User 1 signature is valid.")
except Exception as e:
    print("User 1 signature is invalid:", e)


# User 2 decrypts the PDF using their private key
decrypted_file = private_key_user2.decrypt(
    cipher,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save the decrypted PDF to a file
output_decrypted_pdf_file = 'decrypted_file.txt'
with open(output_decrypted_pdf_file, 'wb') as file:
    file.write(decrypted_file)

print("User 2 decrypts the PDF using their private key. Decrypted file:", output_decrypted_pdf_file)

encrypted_hash = hash(cipher)
decrypted_hash = hash(decrypted_file)

print("Hash of encrypted file:", encrypted_hash.hex())
print("Hash of decrypted file:", decrypted_hash.hex())

#Verifying the Hash value with Main file
if (pdf_hash == decrypted_hash):
 print('Text file verified:- HASH MATCHED')
else:
 print('HASH FILE MISMATCHED')
