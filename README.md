# NFC Secure Communication Project
## Overview

This project implements a secure data exchange system between two NFC-enabled devices using asymmetric encryption. The application is simulated in a Linux environment using Inter-Process Communication (IPC) to ensure bidirectional encrypted communication.

## Technologies Used

- Python: Programming language used for implementing the application.
Cryptography Library: For cryptographic operations, including RSA encryption and PKI management.
- Flask: For creating the Certificate Authority (CA) server that issues and manages certificates.
- sysv_ipc: For IPC communication, simulating the exchange of encrypted data between devices.
Key Concepts
## Asymmetric Encryption and RSA Algorithm
Asymmetric encryption, also known as public-key cryptography, uses a pair of keys: a public key and a private key. RSA (Rivest-Shamir-Adleman) is one of the most widely used algorithms for asymmetric encryption.

- Public Key: Used to encrypt data. It can be shared openly.
- Private Key: Used to decrypt data. It is kept secret.
In this project, RSA is used to secure the data exchanged between devices, ensuring that only the intended recipient can decrypt the data.

## Public Key Infrastructure (PKI)
PKI is a framework for managing digital certificates and public-key encryption. It involves:

- Certificate Authority (CA): A trusted entity that issues digital certificates. In this project, a CA is implemented using Flask to sign and manage certificates for devices.
- Certificates: Digital documents that associate a public key with an identity. Certificates are used to verify the authenticity of the public keys.
Mutual Authentication Using Certificates
Mutual authentication ensures that both devices in the communication process authenticate each other using their certificates. The steps involved include:

- Certificate Signing Request (CSR): Devices generate CSRs and send them to the CA.
- Certificate Issuance: The CA signs and issues certificates based on the CSRs.
Authentication: Devices use their certificates to verify each other’s identities.

## How It Works
- Certificate Generation: Devices generate their own key pairs and CSRs, which are sent to the CA for signing.
- Certificate Management: The CA signs the CSRs and issues certificates to the devices.
Data Exchange: Using IPC communication, the devices exchange encrypted data. The data is encrypted with the recipient’s public key and decrypted with their private key.

## Running the Simulation
Start the CA Server: Run the CA server to handle certificate signing and management.
sh
python3 ca_server.py
Run Device Scripts: Start each device script in separate terminals.
sh
python3 Device_A.py

sh
python3 Device_B.py



## Acknowledgements
Cryptography Library Documentation: For details on cryptographic operations.
Flask Documentation: For setting up the CA server.
sysv_ipc Documentation: For IPC communication in Linux.
