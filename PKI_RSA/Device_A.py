import sysv_ipc
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import random_serial_number
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
import time
import logging
import sys
import os


# Generate keys
Device_A_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
Device_A_public_key = Device_A_private_key.public_key()


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
            x509.NameAttribute(NameOID.COMMON_NAME, u"Device_A"),
        ])
    )
    .sign(Device_A_private_key, hashes.SHA256(), backend=default_backend())
)

# Send CSR to CA server
csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
response = requests.post('http://localhost:5001/sign_csr', json={'csr': csr_pem})

# Save device private key and certificate
with open("Device_A_private_key.pem", "wb") as f:
    f.write(
        Device_A_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

signed_cert_pem_A = response.json().get('certificate')
if signed_cert_pem_A:
    with open("Device_A_certificate.pem", "wb") as f:
        f.write(signed_cert_pem_A.encode())
else:
    print("Error: 'certificate' not found in the response.")

print("Device private key and signed certificate saved.")

time.sleep(4)


try:
    with open("Device_B_certificate.pem", "r") as cert_file:
        Device_B_certificate_pem = cert_file.read()
except FileNotFoundError:
    print("Device B's certificate file not found.")
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



# After fetching Device B's certificate, verify it using the CA's public key
device_B_cert = x509.load_pem_x509_certificate(Device_B_certificate_pem.encode(), default_backend())
ca_public_key.verify(
    device_B_cert.signature,
    device_B_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    device_B_cert.signature_hash_algorithm, 
)

device_B_public_key = device_B_cert.public_key()  # Extract Device B's public key for future use
print("Device B certificate verified and public key loaded.")



def encrypt_and_send_data(data, device_B_public_key):
    # Ensure data is in bytes format
    if isinstance(data, str):
        data = data.encode()
    
    encrypted_data = device_B_public_key.encrypt(
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



key_A = 1234  
key_B = 5678


message_queue_A = sysv_ipc.MessageQueue(key_A, sysv_ipc.IPC_CREAT)
message_queue_B = sysv_ipc.MessageQueue(key_B, sysv_ipc.IPC_CREAT)

#clear_queue(message_queue_A)
#clear_queue(message_queue_B)



while True:

    message_A = "Hello from Device A"
    encrypted_message_A = encrypt_and_send_data(message_A,device_B_public_key)
    message_queue_A.send(encrypted_message_A)
    print("Encrypted data sent successfully.")
    
    time.sleep(1)    
    receive_and_decrypt_message(message_queue_B, Device_A_private_key)
    #time.sleep(1)


