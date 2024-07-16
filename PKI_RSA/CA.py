from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import random_serial_number
import datetime

#generate CA private key 
print("Generating CA private key")
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

print("Generating CA public key")
ca_public_key = ca_private_key.public_key()


#Building CA name and attributes
print("Building CA certificate")
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nabeul"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nabeul"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My Company CA"),
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

print("CA private key and certificate created and saved.")




# Generate user private key 
print("Generating user private key")
user_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)


#Generate user public key 
print("Generating user public key")
user_public_key = user_private_key.public_key()

#Signing the user_certificate
print("Creating certificate signing request (CSR)")
csr = (
    x509.CertificateSigningRequestBuilder()
    .subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"TN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Nabeul"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Nabeul"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"My Company CA"),
        ])
    )
    .sign(user_private_key, hashes.SHA256(), backend=default_backend())
)

#building
print("Building user certificate signed by CA")
user_certificate = (
    x509.CertificateBuilder()
    .subject_name(csr.subject)
    .issuer_name(ca_certificate.subject)
    .public_key(user_public_key)
    .serial_number(random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    .sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())
)

#saving user private key
with open("user_private_key.pem", "wb") as f:
    f.write(
        user_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

#saving user cerificate
with open("user_certificate.pem", "wb") as f:
    f.write(user_certificate.public_bytes(serialization.Encoding.PEM))

print("User key and signed certificate created and saved.")








# Load CA certificate
with open("ca_certificate.pem", "rb") as f:
    ca_cert_data = f.read()

# Load user certificate
with open("user_certificate.pem", "rb") as f:
    user_cert_data = f.read()

# Decode CA certificate
ca_cert = x509.load_pem_x509_certificate(ca_cert_data, default_backend())

# Decode user certificate
user_cert = x509.load_pem_x509_certificate(user_cert_data, default_backend())

# Save certificate details to a text file
with open("certificate_details.txt", "w") as f:
    # Write CA Certificate details
    f.write("----- CA Certificate Details -----\n")
    f.write(f"Subject: {ca_cert.subject.rfc4514_string()}\n")
    f.write(f"Issuer: {ca_cert.issuer.rfc4514_string()}\n")
    f.write(f"Serial Number: {ca_cert.serial_number}\n")
    f.write(f"Not Before: {ca_cert.not_valid_before}\n")
    f.write(f"Not After: {ca_cert.not_valid_after}\n")
    f.write("Extensions:\n")
    for ext in ca_cert.extensions:
        f.write(f"  {ext.oid}: {ext.value}\n")

    # Write User Certificate details
    f.write("\n----- User Certificate Details -----\n")
    f.write(f"Subject: {user_cert.subject.rfc4514_string()}\n")
    f.write(f"Issuer: {user_cert.issuer.rfc4514_string()}\n")
    f.write(f"Serial Number: {user_cert.serial_number}\n")
    f.write(f"Not Before: {user_cert.not_valid_before}\n")
    f.write(f"Not After: {user_cert.not_valid_after}\n")
    f.write("Extensions:\n")
    for ext in user_cert.extensions:
        f.write(f"  {ext.oid}: {ext.value}\n")

print("Certificate details saved to certificate_details.txt.")