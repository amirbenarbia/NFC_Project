import sysv_ipc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.x509 import load_pem_x509_certificate

# Load the private key
with open('user_private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

# Load the user's certificate
with open('user_certificate.pem', 'rb') as f:
    user_certificate = load_pem_x509_certificate(f.read(), default_backend())

# Generate or load the IPC key
key = 1234  # Replace with your desired key

# Try to access the message queue
try:
    message_queue = sysv_ipc.MessageQueue(key)
    print("Message queue accessed successfully.")
except sysv_ipc.ExistentialError:
    print("No queue exists with the specified key. Ensure the sender script has been run first.")
    exit(1)

# Receive the encrypted message
print("Waiting for message...")
try:
    message, _ = message_queue.receive()
    encrypted_message = message  # Extract the message content

    # Display the encrypted message
    print(f"Encrypted message received: {encrypted_message.hex()}")

    # Decrypt the message with the private key
    decrypted_message = private_key.decrypt(
        encrypted_message,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Display the decrypted message
    print(f"Decrypted message: {decrypted_message.decode()}")

except ValueError as e:
    print(f"Error receiving message: {e}")
