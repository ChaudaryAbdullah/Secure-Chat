"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 
#!/usr/bin/env python3
"""
Root Certificate Authority (CA) Generator
Generates a self-signed root CA certificate for the secure chat PKI
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_root_ca():
    """Generate root CA private key and self-signed certificate"""
    
    print("[*] Generating Root CA...")
    
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    # Generate RSA private key for CA (4096 bits for CA security)
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    
    # Define CA subject and issuer (self-signed, so they're the same)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Root CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    # Self-sign the certificate
    ca_certificate = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save private key (encrypted with password)
    with open("certs/ca_private_key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"securechat_ca_password")
        ))
    
    # Save certificate
    with open("certs/ca_certificate.pem", "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    
    print("Root CA generated successfully!")
    print(f"    Private Key: certs/ca_private_key.pem")
    print(f"    Certificate: certs/ca_certificate.pem")
    print(f"    Valid until: {ca_certificate.not_valid_after}")
    
    return ca_private_key, ca_certificate

if __name__ == "__main__":
    generate_root_ca()