from cryptography.hazmat.primitives import serialization, hashes # For key serialization and hash algorithms
from cryptography.hazmat.primitives.asymmetric import rsa  # For RSA key generation and handling
from cryptography.hazmat.backends import default_backend ## Default cryptographic backend for operations
from cryptography import x509 # For creating and managing X509 certificates
from cryptography.x509.oid import NameOID # OID (Object Identifier) for defining certificate attributes
from cryptography.x509 import random_serial_number # To generate a random serial number for certificates

import datetime # To handle dates and times for certificate validity periods
from flask  import Flask, request, jsonify # Flask is used to create a simple HTTP server
import logging # For logging debug/info messages



# Initialize Flask app for handling CSR requests
app = Flask(__name__)

# Set logging level to DEBUG to capture all log messages
logging.basicConfig(level=logging.DEBUG)


# Dictionaries to store device certificates 
device_certificates = {}

# Generate the CA's private key (RSA with 2048-bit key size)
logging.debug("Generating CA private key")
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,  # Standard public exponent for RSA
    key_size=2048, # Key size for the RSA algorithm (2048-bit)
    backend=default_backend() # Use the default cryptographic backend
)


# Generate the corresponding CA public key from the private key
logging.debug("Generating CA public key")
ca_public_key = ca_private_key.public_key()



# Define the CA's distinguished name and certificate attributes
print("Building CA certificate")
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),# Country (TN for Tunisia)
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nabeul"), # State or Province
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nabeul"), # Locality (City)
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),  # Organization name
    x509.NameAttribute(NameOID.COMMON_NAME, u"CA"), # Common name (for the CA)
])


# Create the CA's X509 certificate
ca_certificate = (
    x509.CertificateBuilder()
    .subject_name(ca_name) # The subject name of the certificate (the CA's identity)
    .issuer_name(ca_name)  # The issuer name (since this is the CA itself, it's self-signed)
    .public_key(ca_public_key) # The CA's public key included in the certificate
    .serial_number(random_serial_number()) # Generate a random serial number for the certificate
    .not_valid_before(datetime.datetime.utcnow())  # Certificate validity start time (current UTC time)
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) # Validity period (1 year)
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True, # Set the certificate as a CA
    )
    .sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend()) # Sign with the private key using SHA-256
)


# Save the CA private key to a file (PEM format)
with open("ca_private_key.pem", "wb") as f:
    f.write(
        ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM, # Encode in PEM format
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # Use OpenSSL private key format
            encryption_algorithm=serialization.NoEncryption(), # No encryption for the private key file
        )
    )

# Save the CA certificate to a file (PEM format)
with open("ca_certificate.pem", "wb") as f:
    f.write(ca_certificate.public_bytes(serialization.Encoding.PEM)) # Save certificate in PEM format

logging.debug("CA private key and certificate created and saved.")  # Log that the CA key and certificate are saved



# Save the CA public key to a separate PEM file
with open("ca_public_key.pem", "wb") as f:
    f.write(
        ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM, # Encode the public key in PEM format
            format=serialization.PublicFormat.SubjectPublicKeyInfo # Standard format for public keys
        )
    )

print("CA public key saved as ca_public_key.pem.") # Notify that the CA public key was saved


# Define a route in the Flask app to handle Certificate Signing Requests (CSRs)
@app.route('/sign_csr',methods=['POST']) # This route listens for POST requests to '/sign_csr'
def sign_csr():
    csr_pem = request.json['csr'] # Extract the CSR (Certificate Signing Request) in PEM format from the request
    logging.info("Signing CSR...")  # Log that the CSR signing process is starting
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend()) # Load the CSR from its PEM-encoded form
     # Create the device certificate based on the received CSR
    device_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject) # Use the subject name from the CSR (the device's identity)
        .issuer_name(ca_certificate.subject) # Issuer name is the CA's name (this CA is signing the certificate)
        .public_key(csr.public_key()) # Use the public key from the CSR
        .serial_number(random_serial_number()) # Generate a random serial number
        .not_valid_before(datetime.datetime.utcnow()) # Certificate validity starts now
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) # Valid for 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,  # Not a CA certificate (for a device)
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend()) # Sign with CA's private key using SHA-256
    )

    # Convert the device certificate to PEM format
    device_cert_pem = device_certificate.public_bytes(serialization.Encoding.PEM).decode()

    # Extract the device name from the CSR's subject (for identification)
    device_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    device_certificates[device_name] = device_cert_pem # Store the signed certificate

    logging.info(f"CSR signed successfully for {device_name}.") # Log the success

    # Return the signed certificate as a JSON response
    return jsonify({'certificate': device_cert_pem})


# Start the Flask server when the script is run directly
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001) # Run the app on all available interfaces (port 5001)





