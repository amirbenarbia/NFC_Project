from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import random_serial_number
from cryptography.hazmat.primitives.asymmetric import padding

import datetime
from flask  import Flask, request, jsonify
import logging
import time



app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)



device_certificates = {}
device_public_keys = {}

#generate CA private key 
logging.debug("Generating CA private key")
ca_private_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=2048,
    backend=default_backend()
)

logging.debug("Generating CA public key")

ca_public_key = ca_private_key.public_key()


#Building CA name and attributes
print("Building CA certificate")
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nabeul"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nabeul"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
])


#Creation de CA 
ca_certificate = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)
    .public_key(ca_public_key) 
    .serial_number(random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    .sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
)


#saving private key fel ca_private_key.pem
with open("ca_private_key.pem", "wb") as f:
    f.write(
        ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

#saving CA fel ca_certificate.pem
with open("ca_certificate.pem", "wb") as f:
    f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))

logging.debug("CA private key and certificate created and saved.")


# Save CA public key to a separate PEM file
with open("ca_public_key.pem", "wb") as f:
    f.write(
        ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("CA public key saved as ca_public_key.pem.")


@app.route('/sign_csr',methods=['POST']) 
def sign_csr():
    csr_pem = request.json['csr'] # to extract pem data 
    logging.info("Signing CSR...")
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend()) #load and decode the csr data 
    device_certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_certificate.subject)
        .public_key(csr.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
    )

    device_cert_pem = device_certificate.public_bytes(serialization.Encoding.PEM).decode()

       # Extract name from CSR to identify the device
    device_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    device_certificates[device_name] = device_cert_pem

    logging.info(f"CSR signed successfully for {device_name}.")

    return jsonify({'certificate': device_cert_pem})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)





