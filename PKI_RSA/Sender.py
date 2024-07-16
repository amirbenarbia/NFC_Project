import sysv_ipc
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate

# Load the user's certificate
with open('user_certificate.pem', 'rb') as f:
    user_certificate = load_pem_x509_certificate(f.read(), default_backend())

# Extract public key from the certificate
public_key = user_certificate.public_key()

# Generate or load the message
message_text = input("Enter message to encrypt and send: ").strip()

# Encrypt the message with the recipient's public key
encrypted_message = public_key.encrypt(
    message_text.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Display encryption details
print("\n----- Encryption Details -----")
print(f"Original message: {message_text}")
print(f"Encrypted message (hex): {encrypted_message.hex()}")
print(f"Public key algorithm: RSA")
print(f"Public key size: {public_key.key_size} bits")

# Generate or load the IPC key
key = 1234  # Replace with your desired key

# Create message queue
message_queue = sysv_ipc.MessageQueue(key, sysv_ipc.IPC_CREAT)

# Send encrypted message to the message queue
message_queue.send(encrypted_message)
print("\nData sent successfully.")
