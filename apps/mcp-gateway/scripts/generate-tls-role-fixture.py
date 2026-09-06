"""Print disposable synthetic test PKI as JSON; never writes or trusts files."""
import datetime
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
end = datetime.datetime(2120, 1, 1, tzinfo=datetime.timezone.utc)
root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "APEX SYNTHETIC TEST ONLY")])


def certificate(name, key, *, ca=False, purpose="client", san=True):
    subject = root_name if ca else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = x509.CertificateBuilder().subject_name(subject).issuer_name(root_name)
    builder = builder.public_key(key.public_key()).serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(start).not_valid_after(end)
    builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
        key_encipherment=not ca, data_encipherment=False, key_agreement=False,
        key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), critical=True)
    if not ca:
        if purpose:
            usage = ExtendedKeyUsageOID.SERVER_AUTH if purpose == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
            builder = builder.add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        if san:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
    return builder.sign(root_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


def private(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


data = {"ca": certificate("root", root_key, ca=True)}
for name, purpose in [("governance", "client"), ("evidence", "client"), ("gateway.test", "server")]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    label = "ingress" if purpose == "server" else name
    data[label] = {"cert": certificate(name, key, purpose=purpose), "key": private(key)}
    if label == "governance":
        data["reissued"] = {"cert": certificate("reissued", key), "key": private(key)}
    if label == "ingress":
        data["noSan"] = {"cert": certificate("gateway.test", key, purpose=purpose, san=False), "key": private(key)}
        data["noEku"] = {"cert": certificate("gateway.test", key, purpose=None), "key": private(key)}
print(json.dumps(data))
