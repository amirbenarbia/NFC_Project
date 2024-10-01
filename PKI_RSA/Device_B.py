import sysv_ipc
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import random_serial_number
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import requests
import time
import logging
import os 
import sys 
import random 
import base64


# Generate keys
Device_B_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
Device_B_public_key = Device_B_private_key.public_key()


# Simple Diffie-Hellman key exchange (same p and g as Device A)
p = 23  # The prime number used in Device A
g = 5   # Generator (same as Device A)

# Device B (Bob) generates a private key and public key
private_key_B = random.randint(1, p - 1)  # Private key: Random number < p
public_key_B = pow(g, private_key_B, p)    # Public key: g^private_key_B % p

# Serialize DH public key to bytes
Device_B_dh_public_bytes = str(public_key_B).encode('utf-8')

with open("Device_B_dh_public.pem", "wb") as f:
    f.write(Device_B_dh_public_bytes)



# Display Device B's RSA public key
rsa_public_key_B_pem = Device_B_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
print("Device B's RSA public key (PEM):\n", rsa_public_key_B_pem.decode())
print("Device B dh public key : ",Device_B_dh_public_bytes)
#Creating CSR 
print("Creating certificate signing request (CSR)")
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nabeul"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nabeul"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Device_B"),
        ])
    )
    .sign(Device_B_private_key, hashes.SHA256(), backend=default_backend())
)


# Send CSR to CA server
csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
response = requests.post('http://localhost:5001/sign_csr', json={'csr': csr_pem})

# Save device private key and certificate
with open("Device_B_private_key.pem", "wb") as f:
    f.write(
        Device_B_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open("Device_B_certificate.pem", "wb") as f:
    signed_cert_pem_B = response.json().get('certificate')
if signed_cert_pem_B:
    with open("Device_B_certificate.pem", "wb") as f:
        f.write(signed_cert_pem_B.encode())
else:
    print("Error: 'certificate' not found in the response.")


print("Device private key and signed certificate saved.")

time.sleep(4)

#Save device private key and certificate
with open("Device_B_private_key.pem", "wb") as f:
    f.write(
        Device_B_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

try:
    with open("Device_A_certificate.pem", "r") as cert_file:
        Device_A_certificate_pem = cert_file.read()
except FileNotFoundError:
    print("Device A's certificate file not found.")
    sys.exit(1)

try:
    with open("ca_public_key.pem", "rb") as ca_public_key_file:
        ca_public_key = serialization.load_pem_public_key(
            ca_public_key_file.read(),
            backend=default_backend()
        )
except FileNotFoundError:
    print("CA's public key file not found.")
    sys.exit(1)

# After fetching Device A's certificate, verify it using the CA's public key
device_A_cert = x509.load_pem_x509_certificate(Device_A_certificate_pem.encode(), default_backend())
ca_public_key.verify(
    device_A_cert.signature,
    device_A_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    device_A_cert.signature_hash_algorithm, 
)

print("Device A certificate verified.")
# Using the simpler DH public key generation
#Device_B_dh_public_bytes = str(public_key_B).encode('utf-8')

#time.sleep(2)

# Step 3: Receive Device A's DH public key
try:
    with open("Device_A_dh_public.pem", "rb") as f:
        Device_A_dh_public_bytes = f.read()
        public_key_A = int(Device_A_dh_public_bytes.decode('utf-8'))
        print("Device A dh public key received : ", public_key_A)

except FileNotFoundError:
    print("Device A's DH public key not found.")
    sys.exit(1)

# Step 4: Compute shared secret
shared_secret_B = pow(public_key_A, private_key_B, p)

# Step 5: Derive a symmetric key using HKDF from the shared secret
symmetric_key_B = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(str(shared_secret_B).encode())

# Step 6: Encrypt Device B's RSA public key with the symmetric key
rsa_public_key_bytes_B = Device_B_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Base64-encode the RSA public key before encryption
rsa_public_key_base64_B = base64.b64encode(rsa_public_key_bytes_B)

# Print Base64-encoded RSA public key before encryption
print(f"Base64-encoded RSA public key (B): {rsa_public_key_base64_B.decode()}")


# Encrypt the Base64-encoded public key
iv = os.urandom(16)
cipher_B = Cipher(algorithms.AES(symmetric_key_B), modes.CFB(iv), backend=default_backend())
encryptor_B = cipher_B.encryptor()
encrypted_rsa_public_key_B = encryptor_B.update(rsa_public_key_base64_B) + encryptor_B.finalize()

# Save encrypted RSA public key for sending to Device B
with open("encrypted_rsa_public_key_B.bin", "wb") as f:
    f.write(iv + encrypted_rsa_public_key_B)

print("Device B RSA public key encrypted and ready for transmission to Device A")


time.sleep(3)

try:
    with open("encrypted_rsa_public_key_A.bin", "rb") as f:
        iv_A = f.read(16)
        encrypted_rsa_public_key_A = f.read()
except FileNotFoundError:
    print("Encrypted RSA public key from Device A not found.")
    sys.exit(1)

# Decrypt Device A's RSA public key
cipher_A = Cipher(algorithms.AES(symmetric_key_B), modes.CFB(iv_A), backend=default_backend())
decryptor_A = cipher_A.decryptor()
decrypted_rsa_public_key_A = decryptor_A.update(encrypted_rsa_public_key_A) + decryptor_A.finalize()

#time.sleep(2)



# Base64-decode after decryption
rsa_public_key_base64_A = base64.b64decode(decrypted_rsa_public_key_A)

# Print decrypted Base64-encoded RSA public key
print(f"Decrypted Base64-encoded RSA public key (A): {rsa_public_key_base64_A}")



# Load the decrypted RSA public key
device_A_public_key = serialization.load_pem_public_key(rsa_public_key_base64_A, backend=default_backend())
print("Device B successfully decrypted and loaded Device A's RSA public key.")



def encrypt_and_send_data(data, device_A_public_key):
    # Ensure data is in bytes format
    if isinstance(data, str):
        data = data.encode()
    
    encrypted_data = device_A_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #print(f"Encrypted data : {encrypted_data.hex()}")
    return encrypted_data


def receive_and_decrypt_message(queue, private_key):
    try:
        encrypted_message, _ = queue.receive()
        decrypted_data = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Decrypted message received: {decrypted_data.decode()}")
    except sysv_ipc.BusyError:
        print("No messages available in the queue.")
    except Exception as e:
        print(f"Decryption failed: {e}")

def clear_message_queue(queue):
    while True:
        try:
            queue.receive(block=False)  # Non-blocking receive to clear queue
        except sysv_ipc.BusyError:
            break  # Stop when the queue is empty




key_A = 1234  
key_B = 5678

message_queue_B = sysv_ipc.MessageQueue(key_B, sysv_ipc.IPC_CREAT)
message_queue_A = sysv_ipc.MessageQueue(key_A, sysv_ipc.IPC_CREAT)

while True:
    # Receive and decrypt messages
    receive_and_decrypt_message(message_queue_A, Device_B_private_key)
    
    
    time.sleep(1)
    
    # Encrypt and send a message
    message_B = "Hello from Device B"
    encrypted_message_B = encrypt_and_send_data(message_B, device_A_public_key)
    message_queue_B.send(encrypted_message_B)
    print("Encrypted data sent successfully.")
    clear_message_queue(message_queue_A)
    clear_message_queue(message_queue_B)

    

    

