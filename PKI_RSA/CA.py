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



@app.route('/send_certificate', methods=['POST'])
def send_certificate():
    data = request.json
    device_name = data.get('device_name')
    cert_pem = data.get('certificate')
    public_key_pem = data.get('public_key')  

    if not device_name or not cert_pem or not public_key_pem:
        return jsonify({'status': 'failure', 'message': 'Device name, certificate, and public key must be provided.'})

    device_certificates[device_name] = cert_pem
    device_public_keys[device_name] = public_key_pem  # Save the public key as well
    logging.info(f"Certificate and public key for {device_name} stored successfully.")
    
    return jsonify({'status': 'success', 'message': f'{device_name} certificate and public key stored successfully.'})


@app.route('/get_certificate', methods=['GET'])
def get_certificate():
    device_name = request.args.get('device_name')
    cert_pem = device_certificates.get(device_name)
    if cert_pem:
        logging.info(f"Certificate for {device_name} retrieved successfully.")
        return jsonify({'certificate': cert_pem})
    else:
        logging.warning(f"Certificate for {device_name} not found.")
        return jsonify({'message': 'Certificate not found'}), 404


@app.route('/authenticate_device_A', methods=['POST'])
def authenticate_device_A():
    request_data = request.json
    device_A_cert_pem = request_data.get('Device_A_certificate')

    if not device_A_cert_pem:
        return jsonify({'status': 'failure', 'error': 'Device_A_certificate is required.'})

    try:
        device_A_cert = x509.load_pem_x509_certificate(device_A_cert_pem.encode(), default_backend())
        #device_A_name = device_A_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Verify Device A's certificate
        ca_public_key.verify(
            device_A_cert.signature,
            device_A_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            device_A_cert.signature_hash_algorithm,
        )

        # Get Device B public key
        device_B_public_key_pem = device_public_keys.get('Device_B')
        if not device_B_public_key_pem:
            return jsonify({'status': 'failure', 'error': 'Device B public key not found.'})

        return jsonify({'status': 'success', 'device_B_public_key': device_B_public_key_pem})

    except Exception as e:
        return jsonify({'status': 'failure', 'error': str(e)})

@app.route('/authenticate_device_B', methods=['POST'])
def authenticate_device_B():
    request_data = request.json
    device_B_cert_pem = request_data.get('Device_B_certificate')

    if not device_B_cert_pem:
        return jsonify({'status': 'failure', 'error': 'Device_B_certificate is required.'})

    try:
        device_B_cert = x509.load_pem_x509_certificate(device_B_cert_pem.encode(), default_backend())
        #device_B_name = device_B_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

        # Verify Device B's certificate
        ca_public_key.verify(
            device_B_cert.signature,
            device_B_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            device_B_cert.signature_hash_algorithm,
        )

        # Get Device A's public key
        device_A_public_key_pem = device_public_keys.get('Device_A')
        if not device_A_public_key_pem:
            return jsonify({'status': 'failure', 'error': 'Device A public key not found.'})

        return jsonify({'status': 'success', 'device_A_public_key': device_A_public_key_pem})

    except Exception as e:
        return jsonify({'status': 'failure', 'error': str(e)})
    


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)





