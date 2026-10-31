"""Generate disposable non-Apple XCTest identity resources. Never accepts owner credentials."""
import os
import pathlib
import secrets
import subprocess
import tempfile

os.umask(0o077)
root = pathlib.Path(__file__).resolve().parents[1]
output = root / 'AppTests/Generated'
output.mkdir(parents=True, exist_ok=True)
password = output / 'fixture-password'
password.write_text(secrets.token_hex(24))
openssl = pathlib.Path('/opt/homebrew/opt/openssl@3/bin/openssl')
openssl = str(openssl) if openssl.exists() else 'openssl'
with tempfile.TemporaryDirectory(prefix='omnisign-xctest-identity-') as temporary:
    key, cert = [pathlib.Path(temporary) / x for x in ['key.pem','certificate.pem']]
    for command in [
        [openssl,'req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-sha256','-subj','/CN=OmniSign XCTest Disposable/OU=OMNILAB123'],
        [openssl,'pkcs12','-export','-inkey',str(key),'-in',str(cert),'-out',str(output / 'fixture.p12'),'-passout','file:' + str(password),'-keypbe','AES-256-CBC','-certpbe','AES-256-CBC','-macalg','SHA256']
    ]:
        subprocess.run(command,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print('Generated disposable XCTest resources locally; no key or password is logged or uploaded.')
