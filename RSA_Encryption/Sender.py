import sysv_ipc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Load the public key
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

# Generate unique key for message queue
key = 1234  # Replace with your desired key (same as in receiver)

# Create message queue
message_queue = sysv_ipc.MessageQueue(key, sysv_ipc.IPC_CREAT)

# Input message from user
message_text = input("Write Data: ").strip()

# Encrypt the message with the public key
encrypted_message = public_key.encrypt(
    message_text.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#Display the encrypted data
print(f"Encrypted message : {encrypted_message.hex()}")

# Send encrypted message to the message queue
message_queue.send(encrypted_message)

print("Data sent successfully.")
