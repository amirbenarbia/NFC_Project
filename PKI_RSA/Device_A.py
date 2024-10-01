import sysv_ipc # Import system V IPC for inter-process communication
from cryptography.hazmat.primitives import hashes, serialization # Import cryptographic primitives
from cryptography.hazmat.primitives.asymmetric import padding  #Import padding for RSA encryption
from cryptography.hazmat.backends import default_backend # Default cryptographic backend
from cryptography.x509 import load_pem_x509_certificate  # Import function to load X509 certificates
from cryptography import x509  # X509 certificate generation and handling
from cryptography.x509.oid import NameOID # OID constants for X509 certificates
from cryptography.x509 import random_serial_number 
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh   # RSA and DH algorithms
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # AES encryption
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # Key derivation function (HKDF)
import requests # Library to handle HTTP requests
import time # Module for delays
import logging # Logging system
import sys # System-specific parameters and functions
import os  # Module to interact with the OS
import random # Random number generation
import base64   # Base64 encoding and decoding


# Step 1: Generate RSA key pair for Device A
# RSA key size: 2048 bits, public exponent: 65537 (standard choice)
Device_A_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
Device_A_public_key = Device_A_private_key.public_key() # Derive public key from the private key




# Step 2: Simple Diffie-Hellman (DH) key exchange setup
p = 23  # Prime number for Diffie-Hellman (this should be a large prime for real security)
g = 5    # Generator (primitive root modulo p)

# Generate Device A's (Alice) DH private and public keys
private_key_A = random.randint(1, p - 1)   # DH private key : Random number < p
public_key_A = pow(g, private_key_A, p)    # DH Public key: g^private_key_A % p

# Serialize the DH public key to bytes for saving and transfer
Device_A_dh_public_bytes = str(public_key_A).encode('utf-8')

# Save the DH public key to a PEM file
with open("Device_A_dh_public.pem", "wb") as f:
    f.write(Device_A_dh_public_bytes)



# Step 3: Display Device A's RSA public key in PEM format
rsa_public_key_A_pem = Device_A_public_key.public_bytes(
    encoding=serialization.Encoding.PEM, # PEM format encoding
    format=serialization.PublicFormat.SubjectPublicKeyInfo # Public key format
)

print("Device A's RSA public key (PEM):\n", rsa_public_key_A_pem.decode())
print("Device A dh public key : ",Device_A_dh_public_bytes)

# Step 4: Create a Certificate Signing Request (CSR) for Device A
print("Creating certificate signing request (CSR)")
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name([
            # Define the CSR subject attributes (country, state, locality, organization, common name)
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nabeul"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nabeul"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"Device_A"),
        ])
    )
    .sign(Device_A_private_key, hashes.SHA256(), backend=default_backend())  # Sign the CSR with the private key
)

# Step 5: Send the CSR to the Certificate Authority (CA) server for signing
csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()  # Serialize the CSR in PEM format
response = requests.post('http://localhost:5001/sign_csr', json={'csr': csr_pem})  # Serialize the CSR in PEM format

# Step 6: Save the private key and signed certificate locally
with open("Device_A_private_key.pem", "wb") as f:
    f.write(
        Device_A_private_key.private_bytes(
            encoding=serialization.Encoding.PEM, # PEM encoding for private key
            format=serialization.PrivateFormat.TraditionalOpenSSL, # Standard format
            encryption_algorithm=serialization.NoEncryption(), # No encryption for the private key
        )
    )

# Save signed certificate received from the CA
with open("Device_A_certificate.pem", "wb") as f:
    signed_cert_pem_A = response.json().get('certificate')  # Get the certificate from the CA's response
if signed_cert_pem_A:
    with open("Device_A_certificate.pem", "wb") as f:
        f.write(signed_cert_pem_A.encode()) # Save the certificate as a PEM file
else:
    print("Error: 'certificate' not found in the response.") # Error handling


print("Device private key and signed certificate saved.")

time.sleep(4) # Delay for synchronization (because we will run each Device code on a seperate terminal)



#Save device private key and certificate
with open("Device_A_private_key.pem", "wb") as f:
    f.write(
        Device_A_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,  # PEM encoding
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # Standard format
            encryption_algorithm=serialization.NoEncryption(), # No encryption
        )
    )

# Try to load Device B's certificate
try:
    with open("Device_B_certificate.pem", "r") as cert_file:
        Device_B_certificate_pem = cert_file.read() # Read Device B's certificate
except FileNotFoundError:
    print("Device B's certificate file not found.")  # Handle missing file
    sys.exit(1)


# Load the CA's public key to verify Device B's certificate
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
    device_B_cert.signature,  # Signature to verify
    device_B_cert.tbs_certificate_bytes, # Data signed
    padding.PKCS1v15(),  # Padding method for verification
    device_B_cert.signature_hash_algorithm,  # Hash algorithm used for signing
)

print("Device B certificate verified.")





# Step 7: Receive Device B's DH public key
try:
    with open("Device_B_dh_public.pem", "rb") as f:
        Device_B_dh_public_bytes = f.read()  # Read Device B's DH public key
        public_key_B = int(Device_B_dh_public_bytes.decode('utf-8')) # Decode public key as an integer
        print("Device B dh public key received : ",public_key_B )
except FileNotFoundError:
    print("Device B's DH public key not found.") # Handle missing file
    sys.exit(1)

# Step 8: Compute shared secret using Device B's public key and Device A's private key
shared_secret_A = pow(public_key_B, private_key_A, p)

# Step 9: Derive a symmetric key using HKDF from the shared secret
symmetric_key_A = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data', backend=default_backend()).derive(str(shared_secret_A).encode())

# Step 10: Encrypt Device A's RSA public key with the symmetric key
rsa_public_key_bytes_A = Device_A_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Encode the RSA public key in base64 for easier transmission
rsa_public_key_base64_A = base64.b64encode(rsa_public_key_bytes_A)
print(f"Base64-encoded RSA public key (A): {rsa_public_key_base64_A.decode()}")

# Encrypt the Base64-encoded public key using AES encryption (CFB mode)
iv = os.urandom(16) # Generate a random initialization vector (IV)
cipher_A = Cipher(algorithms.AES(symmetric_key_A), modes.CFB(iv), backend=default_backend())
encryptor_A = cipher_A.encryptor()
encrypted_rsa_public_key_A = encryptor_A.update(rsa_public_key_base64_A) + encryptor_A.finalize()

# Save encrypted RSA public key for sending to Device B
with open("encrypted_rsa_public_key_A.bin", "wb") as f:
    f.write(iv + encrypted_rsa_public_key_A)  # Save IV and encrypted data


print("Device A RSA public key encrypted and ready for transmission to Device B.")



time.sleep(3) # Delay for synchronization (to wait the other davice to encrypt its RSA public key)


# Try to load the encrypted RSA public key from Device B
try:
    with open("encrypted_rsa_public_key_B.bin", "rb") as f:
        iv_B = f.read(16) # Read initialization vector
        encrypted_rsa_public_key_B = f.read() # Read encrypted RSA public key
except FileNotFoundError:
    print("Encrypted RSA public key from Device B not found.") # Handle missing file
    sys.exit(1)

# Decrypt Device B's RSA public key using the shared symmetric key
cipher_B = Cipher(algorithms.AES(symmetric_key_A), modes.CFB(iv_B), backend=default_backend())
decryptor_B = cipher_B.decryptor()
decrypted_rsa_public_key_B = decryptor_B.update(encrypted_rsa_public_key_B) + decryptor_B.finalize()




# Base64-decode after decryption to get the original RSA public key
rsa_public_key_base64_B = base64.b64decode(decrypted_rsa_public_key_B)

# Print decrypted Base64-encoded RSA public key
print(f"Decrypted Base64-encoded RSA public key (B): {rsa_public_key_base64_B}")



# Load the decrypted RSA public key
device_B_public_key = serialization.load_pem_public_key(rsa_public_key_base64_B, backend=default_backend())
print("Device A successfully decrypted and loaded Device B's RSA public key.")



# Function to encrypt and send data using Device B's public key
def encrypt_and_send_data(data, device_B_public_key):
    # Ensure data is in bytes format
    if isinstance(data, str):
        data = data.encode()
    
    # Encrypt the data using RSA and OAEP padding
    encrypted_data = device_B_public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), # Mask generation function
            algorithm=hashes.SHA256(), # Hash algorithm
            label=None
        )
    )
    return encrypted_data


# Function to receive and decrypt a message from the message queue
def receive_and_decrypt_message(queue, private_key):
    try:
        encrypted_message, _ = queue.receive()  # Receive the encrypted message from the queue
        decrypted_data = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), # Mask generation function
                algorithm=hashes.SHA256(), # Hash algorithm
                label=None
            )
        )
        print(f"Decrypted message received: {decrypted_data.decode()}")
    except sysv_ipc.BusyError:
        print("No messages available in the queue.") # Handle empty queue
    except Exception as e:
        print(f"Decryption failed: {e}") # Handle decryption error


# Function to clear the message queue
def clear_message_queue(queue):
    while True:
        try:
            queue.receive(block=False)  # Non-blocking receive to clear queue
        except sysv_ipc.BusyError:
            break  # Stop when the queue is empty


key_A = 1234  # Message queue key for Device A
key_B = 5678  # Message queue key for Device B


# Create message queues for Device A and Device B
message_queue_A = sysv_ipc.MessageQueue(key_A, sysv_ipc.IPC_CREAT)
message_queue_B = sysv_ipc.MessageQueue(key_B, sysv_ipc.IPC_CREAT)




# Main loop for sending and receiving messages
while True:

    message_A = "Hello from Device A"   # Message to send
    encrypted_message_A = encrypt_and_send_data(message_A,device_B_public_key) # Encrypt the message
    message_queue_A.send(encrypted_message_A)# Send the encrypted message to Device B
    print("Encrypted data sent successfully.")
    
    time.sleep(1)     # Delay for synchronization
    receive_and_decrypt_message(message_queue_B, Device_A_private_key) # Receive and decrypt the message from Device B
    
    clear_message_queue(message_queue_A)  # Clear Device A's message queue
    clear_message_queue(message_queue_B)  # Clear Device B's message queue




