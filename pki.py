"""CA propia del proyecto y certificado TLS del servidor local.

  py pki.py init      # crea la CA raíz y un certificado de servidor firmado por ella
  py pki.py server    # renueva solo el certificado del servidor (misma CA)
  py pki.py verify    # valida la cadena servidor -> CA, SAN, vigencia y uso de clave
  py pki.py show      # imprime huellas SHA-256 para comprobarlas al instalar la CA

Diseño (ver informe, sección de certificados):
- CA raíz: ECDSA P-384, válida 5 años, BasicConstraints CA=true pathlen=0, KeyUsage keyCertSign/cRLSign.
  Su clave privada se guarda cifrada (PKCS#8 + AES-256) con una frase de paso aleatoria en ``ca.pass``.
- Servidor: ECDSA P-256, válido 397 días (límite aceptado por navegadores), SAN localhost/127.0.0.1/::1,
  ExtendedKeyUsage serverAuth, KeyUsage digitalSignature, sin capacidad de firmar otros certificados.
Para que el navegador confíe en el servidor, instala ``instance/pki/ca.crt`` como raíz de confianza
solo en el equipo de la demo y elimínala al terminar el curso.
"""
import argparse
import datetime as dt
import ipaddress
import os
import secrets
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from db_crypto import INSTANCE, private_dir

PKI = INSTANCE / "pki"
CA_CRT, CA_KEY, CA_PASS = PKI / "ca.crt", PKI / "ca.key", PKI / "ca.pass"
SRV_CRT, SRV_KEY = PKI / "server.crt", PKI / "server.key"
SAN = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
       x509.IPAddress(ipaddress.ip_address("::1"))]


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _write(path, data, mode=0o600):
    private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "PE"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Olist Lab DS3031 (academico)"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def create_ca():
    key = ec.generate_private_key(ec.SECP384R1())
    name = _name("Olist Lab Root CA")
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5))
            .not_valid_after(_now() + dt.timedelta(days=5 * 365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ski, critical=False)
            .sign(key, hashes.SHA384()))
    passphrase = secrets.token_urlsafe(32).encode()
    _write(CA_PASS, passphrase)
    _write(CA_KEY, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.BestAvailableEncryption(passphrase)))
    _write(CA_CRT, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    print(f"CA raíz creada: {CA_CRT}")


def load_ca():
    if not CA_CRT.exists():
        raise SystemExit("No existe la CA. Ejecuta: py pki.py init")
    cert = x509.load_pem_x509_certificate(CA_CRT.read_bytes())
    key = serialization.load_pem_private_key(CA_KEY.read_bytes(), CA_PASS.read_bytes())
    return cert, key


def issue_server():
    ca_cert, ca_key = load_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name("localhost")).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(_now() - dt.timedelta(minutes=5))
            .not_valid_after(_now() + dt.timedelta(days=397))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(SAN), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    _write(SRV_KEY, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
    _write(SRV_CRT, cert.public_bytes(serialization.Encoding.PEM), 0o644)
    print(f"Certificado de servidor emitido por la CA propia: {SRV_CRT}")


def verify():
    """Valida la cadena con la propia pila TLS de Python, como lo haría un cliente."""
    ca = x509.load_pem_x509_certificate(CA_CRT.read_bytes())
    srv = x509.load_pem_x509_certificate(SRV_CRT.read_bytes())
    srv.verify_directly_issued_by(ca)
    now = _now()
    eku = srv.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    names = srv.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    # Comprobaciones explícitas (no assert: python -O las eliminaría; hallazgo B101 de Bandit).
    problems = [msg for failed, msg in (
        (not srv.not_valid_before_utc <= now <= srv.not_valid_after_utc, "certificado fuera de vigencia"),
        (srv.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, "el servidor no debe ser CA"),
        (ExtendedKeyUsageOID.SERVER_AUTH not in eku, "falta serverAuth"),
        ("localhost" not in names.get_values_for_type(x509.DNSName), "falta localhost en SAN"),
    ) if failed]
    if problems:
        raise ValueError("Certificado inválido: " + "; ".join(problems))
    context = ssl.create_default_context(cafile=str(CA_CRT))
    context.load_cert_chain(SRV_CRT, SRV_KEY)  # la clave corresponde al certificado
    days = (srv.not_valid_after_utc - now).days
    print(f"OK: servidor firmado por '{ca.subject.rfc4514_string()}', SAN={names.get_values_for_type(x509.DNSName)}"
          f" + IP, serverAuth, vigente {days} días más.")


def show():
    for label, path in (("CA raíz", CA_CRT), ("Servidor", SRV_CRT)):
        cert = x509.load_pem_x509_certificate(path.read_bytes())
        print(f"{label}: {cert.subject.rfc4514_string()}\n  SHA-256: {cert.fingerprint(hashes.SHA256()).hex(':').upper()}"
              f"\n  Vigencia: {cert.not_valid_before_utc:%Y-%m-%d} -> {cert.not_valid_after_utc:%Y-%m-%d}")


def server_context():
    """Contexto TLS del servidor: mínimo TLS 1.2 y certificado emitido por la CA propia."""
    if not (SRV_CRT.exists() and SRV_KEY.exists()):
        raise SystemExit("Falta el certificado del servidor. Ejecuta: py pki.py init")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(SRV_CRT, SRV_KEY)
    return context


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["init", "server", "verify", "show"])
    args = parser.parse_args()
    if args.command == "init":
        if CA_CRT.exists():
            print("La CA ya existe; se conserva y solo se renueva el certificado del servidor.")
        else:
            create_ca()
        issue_server()
        verify()
    elif args.command == "server":
        issue_server()
        verify()
    elif args.command == "verify":
        verify()
    else:
        show()
