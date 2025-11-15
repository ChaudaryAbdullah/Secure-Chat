"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
#!/usr/bin/env python3
"""
Certificate Generator for Server and Client
Issues X.509 certificates signed by the Root CA
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import sys
import os

def load_ca():
    """Load CA private key and certificate"""
    
    # Load CA private key
    with open("certs/ca_private_key.pem", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=b"securechat_ca_password",
            backend=default_backend()
        )
    
    # Load CA certificate
    with open("certs/ca_certificate.pem", "rb") as f:
        ca_certificate = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_private_key, ca_certificate

def generate_certificate(entity_type, common_name):
    """
    Generate and sign a certificate for server or client
    
    Args:
        entity_type: 'server' or 'client'
        common_name: CN for the certificate (e.g., 'localhost' or 'client1')
    """
    
    print(f"[*] Generating {entity_type} certificate for '{common_name}'...")
    
    # Load CA
    ca_private_key, ca_certificate = load_ca()
    
    # Generate private key for entity (2048 bits for end entities)
    entity_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Define subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, entity_type.capitalize()),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(entity_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                key_cert_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(entity_private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    # Add Subject Alternative Name for server
    if entity_type == "server":
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    
    # Sign certificate with CA
    entity_certificate = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save private key (unencrypted for ease of use - in production, encrypt this!)
    key_filename = f"certs/{entity_type}_private_key.pem"
    with open(key_filename, "wb") as f:
        f.write(entity_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    cert_filename = f"certs/{entity_type}_certificate.pem"
    with open(cert_filename, "wb") as f:
        f.write(entity_certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"[✓] {entity_type.capitalize()} certificate generated successfully!")
    print(f"    Private Key: {key_filename}")
    print(f"    Certificate: {cert_filename}")
    print(f"    Valid until: {entity_certificate.not_valid_after}")
    
    return entity_private_key, entity_certificate

if __name__ == "__main__":
    import ipaddress
    
    if len(sys.argv) != 3:
        print("Usage: python gen_cert.py <server|client> <common_name>")
        print("Example: python gen_cert.py server localhost")
        print("Example: python gen_cert.py client alice@example.com")
        sys.exit(1)
    
    entity_type = sys.argv[1].lower()
    common_name = sys.argv[2]
    
    if entity_type not in ["server", "client"]:
        print("Error: entity_type must be 'server' or 'client'")
        sys.exit(1)
    
    # Check if CA exists
    if not os.path.exists("certs/ca_certificate.pem"):
        print("Error: CA certificate not found. Run gen_ca.py first.")
        sys.exit(1)
    
    generate_certificate(entity_type, common_name)
