import sysv_ipc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Load the private key
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Generate unique key for message queue
key = 1234  # Replace with your desired key (same as in sender)

# Try to access the message queue
try:
    message_queue = sysv_ipc.MessageQueue(key)
except sysv_ipc.ExistentialError:
    print("No queue exists with the specified key. Ensure the sender script has been run first.")
    exit(1)

# Receive encrypted message from the message queue
encrypted_message, _ = message_queue.receive()

#Display the encrypted message received
print(f"Encrypted message received: {encrypted_message.hex()}")

# Decrypt the message with the private key
decrypted_message = private_key.decrypt(
    encrypted_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print(f"Data received is: {decrypted_message.decode()}")

# Optionally, remove the message queue
message_queue.remove()
