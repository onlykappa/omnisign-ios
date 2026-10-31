"""Disposable signing experiment. No Apple account, installation, or owner signing assets."""
import hashlib
import json
import os
import pathlib
import plistlib
import secrets
import struct
import subprocess
import sys
import tempfile


def run(args, stage):
    result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        # Never emit backend errors that could contain key/password buffers.
        raise RuntimeError(f'{stage} failed (exit {result.returncode}); generated secrets are not logged')
    return result.stdout


def signature_parts(binary):
    data = binary.read_bytes()
    if data[:4] != bytes.fromhex('cffaedfe') or len(data) < 32:
        raise RuntimeError('Fixture must be thin little-endian Mach-O 64')
    count, command_bytes = struct.unpack_from('<II', data, 16)
    if count > 4096 or command_bytes > len(data) - 32:
        raise RuntimeError('Invalid Mach-O commands')
    pos = 32
    signature = None
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, pos)
        if size < 8 or pos + size > 32 + command_bytes:
            raise RuntimeError('Invalid load command')
        if cmd == 0x1D:
            offset, length = struct.unpack_from('<II', data, pos + 8)
            if offset + length > len(data) or signature is not None:
                raise RuntimeError('Invalid signature range')
            signature = data[offset:offset + length]
        pos += size
    if signature is None:
        raise RuntimeError('No generated code signature')
    magic, total, entries = struct.unpack_from('>III', signature)
    if magic != 0xFADE0CC0 or total > len(signature) or entries > 64 or 12 + 8 * entries > total:
        raise RuntimeError('Invalid signature superblob')
    blobs = {}
    for i in range(entries):
        slot, offset = struct.unpack_from('>II', signature, 12 + 8 * i)
        if offset < 12 + 8 * entries or offset + 8 > total or slot in blobs:
            raise RuntimeError('Invalid blob index')
        _, length = struct.unpack_from('>II', signature, offset)
        if length < 8 or offset + length > total:
            raise RuntimeError('Invalid nested signature blob')
        blobs[slot] = signature[offset:offset + length]
    return data, blobs


def verify_target(binary, bundle, cert, temp, openssl, swift_lab):
    data, blobs = signature_parts(binary)
    cd = blobs[0]
    if struct.unpack_from('>I', cd)[0] != 0xFADE0C02:
        raise RuntimeError('Missing CodeDirectory')
    hash_offset, _, special, slots, limit = struct.unpack_from('>IIIII', cd, 16)
    hash_size, hash_type, _, page_exp = struct.unpack_from('BBBB', cd, 36)
    if hash_size != 32 or hash_type != 2 or page_exp > 20 or limit > len(data) or special > 64:
        raise RuntimeError('Unsupported CodeDirectory fixture layout')
    page_size = 1 << page_exp
    if slots != (limit + page_size - 1) // page_size or hash_offset + slots * 32 > len(cd) or hash_offset - special * 32 < 0:
        raise RuntimeError('Invalid page-hash bounds')
    for index in range(slots):
        actual = hashlib.sha256(data[index * page_size:min((index + 1) * page_size, limit)]).digest()
        if actual != cd[hash_offset + index * 32:hash_offset + (index + 1) * 32]:
            raise RuntimeError('Code page hash mismatch')
    expected_special = {2: blobs.get(2), 5: blobs.get(5), 7: blobs.get(7)}
    if bundle:
        expected_special[1] = (bundle / 'Info.plist').read_bytes()
        resource = bundle / '_CodeSignature/CodeResources'
        if resource.exists():
            expected_special[3] = resource.read_bytes()
            seal = plistlib.loads(resource.read_bytes())
            for name, value in seal.get('files2', {}).items():
                file = bundle / name
                if name.startswith('/') or '..' in pathlib.PurePosixPath(name).parts or file.is_symlink():
                    raise RuntimeError('Unsafe sealed resource')
                if isinstance(value, dict) and 'hash2' in value:
                    if hashlib.sha256(file.read_bytes()).digest() != value['hash2']:
                        raise RuntimeError('Resource hash mismatch')
    for slot, value in expected_special.items():
        if value is not None:
            if slot > special or hashlib.sha256(value).digest() != cd[hash_offset - slot * 32:hash_offset - (slot - 1) * 32]:
                raise RuntimeError('Special-slot resource/requirements hash mismatch')
    wrapped = blobs[0x10000]
    if struct.unpack_from('>I', wrapped)[0] != 0xFADE0B01:
        raise RuntimeError('Missing CMS signature wrapper')
    directory = temp / 'directory.bin'; cms = temp / 'signature.der'
    directory.write_bytes(cd); cms.write_bytes(wrapped[8:])
    # Explicitly trust ONLY the generated fixture leaf for this mathematical CMS test.
    # This is not Apple chain/development authorization.
    run([openssl, 'cms', '-verify', '-binary', '-inform', 'DER', '-in', cms, '-content', directory, '-CAfile', cert, '-purpose', 'any', '-out', os.devnull], 'independent OpenSSL CMS verification')
    run([swift_lab, '--verify-cms', cms, directory], 'independent Swift CMS mathematics')


def main():
    if sys.platform != 'darwin' or len(sys.argv) != 2:
        raise RuntimeError('This fixture harness requires macOS/Xcode and the compiled lab executable')
    os.umask(0o077)
    lab = pathlib.Path(sys.argv[1]).resolve()
    openssl = 'openssl'
    brew_ssl = pathlib.Path('/opt/homebrew/opt/openssl@3/bin/openssl')
    if brew_ssl.exists():
        openssl = str(brew_ssl)
    with tempfile.TemporaryDirectory(prefix='omnisign-disposable-') as temporary:
        temp = pathlib.Path(temporary)
        key, cert, identity, password = [temp / x for x in ['key.pem', 'certificate.pem', 'identity.p12', 'password']]
        password.write_text(secrets.token_hex(24))
        run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '1', '-sha256', '-subj', '/CN=OmniSign Disposable Lab/OU=OMNILAB123'], 'generate disposable identity')
        run([openssl, 'pkcs12', '-export', '-inkey', key, '-in', cert, '-out', identity, '-passout', 'file:' + str(password), '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC', '-macalg', 'SHA256'], 'package disposable identity')
        sdk = run(['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'], 'resolve iPhone SDK').decode().strip()
        root = temp / 'Lab.app'; framework = root / 'Frameworks/LabFramework.framework'; extension = root / 'PlugIns/LabWidget.appex'
        for folder, name, identifier, package in [(root, 'Lab', 'org.omnisign.lab', 'APPL'), (framework, 'LabFramework', 'org.omnisign.lab.framework', 'FMWK'), (extension, 'LabWidget', 'org.omnisign.lab.widget', 'XPC!')]:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / 'Info.plist').write_bytes(plistlib.dumps(dict(CFBundleIdentifier=identifier, CFBundleExecutable=name, CFBundleName=name, CFBundleVersion='1', CFBundleShortVersionString='1.0', CFBundlePackageType=package, CFBundleSupportedPlatforms=['iPhoneOS'], MinimumOSVersion='17.0')))
        source = temp / 'fixture.c'; source.write_text('int main(void) { return 0; }\n')
        dylib = root / 'Frameworks/libExtra.dylib'
        targets = [(root / 'Lab', root), (framework / 'LabFramework', framework), (extension / 'LabWidget', extension), (dylib, None)]
        for binary, _ in targets:
            args = ['xcrun', '--sdk', 'iphoneos', 'clang', '-arch', 'arm64', '-isysroot', sdk, '-miphoneos-version-min=17.0', '-Wl,-no_adhoc_codesign', source, '-o', binary]
            if binary in [framework / 'LabFramework', dylib]:
                args.append('-dynamiclib')
            run(args, 'compile disposable Mach-O')
        sentinel = root / 'sentinel.txt'; sentinel.write_text('disposable resource\n')
        run([lab, root, identity, password], 'experimental CodeSignKit signing')
        for binary, bundle in targets:
            verify_target(binary, bundle, cert, temp, openssl, lab)
        print('PASS: four generated targets have independently verified code-page/special-slot hashes and CMS signatures against the synthetic fixture identity.')
        native = subprocess.run(['codesign', '--verify', '--deep', '--strict', str(root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        native_accepted = native.returncode == 0
        native_text = native.stderr.decode(errors='replace').lower()
        native_category = 'accepted' if native_accepted else 'unclassified-native-rejection'
        for needle, category in [('not trusted','certificate-trust'),('cssmerr_tp_not_trusted','certificate-trust'),('requirements','requirements'),('requirement','requirements'),('resource','resource-envelope'),('invalid signature','signature'),('not signed','unsigned')]:
            if needle in native_text:
                native_category = category
                break
        print('Apple codesign verifier accepted synthetic output: ' + str(native_accepted).lower())
        print('Native verification result category: ' + native_category)
        # Controlled generated app only: codesign never receives the P12/password/key paths.
        native_detail = native.stderr.decode(errors='replace').replace(str(temp), '<generated-fixture>')[:1200]
        if native_detail:
            print('Native verifier diagnostic (generated fixture only): ' + native_detail.strip())
        requirement_parsed = None
        _, root_blobs = signature_parts(root / 'Lab')
        requirement_set = root_blobs.get(2)
        if requirement_set and len(requirement_set) >= 20:
            count = struct.unpack_from('>I', requirement_set, 8)[0]
            if count == 1:
                slot, offset = struct.unpack_from('>II', requirement_set, 12)
                if slot == 3 and offset + 8 <= len(requirement_set):
                    length = struct.unpack_from('>I', requirement_set, offset + 4)[0]
                    if offset + length <= len(requirement_set):
                        file = temp / 'generated-requirement.bin'
                        file.write_bytes(requirement_set[offset:offset + length])
                        parsed = subprocess.run(['csreq','-r',str(file),'-t'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                        requirement_parsed = parsed.returncode == 0
                        print('Native designated-requirement parser accepted candidate blob: ' + str(requirement_parsed).lower())
        # Prove code-page and CMS corruption fail independently, not just resource changes.
        framework_binary = framework / 'LabFramework'
        original = framework_binary.read_bytes()
        _, framework_blobs = signature_parts(framework_binary)
        cd = framework_blobs[0]
        code_limit = struct.unpack_from('>I', cd, 32)[0]
        corrupted = bytearray(original)
        corrupted[min(4096, code_limit - 1)] ^= 1
        framework_binary.write_bytes(corrupted)
        try:
            verify_target(framework_binary, framework, cert, temp, openssl, lab)
        except RuntimeError:
            print('PASS: independent verification rejects code-page tampering.')
        else:
            raise RuntimeError('Code-page tampering was not detected')
        finally:
            framework_binary.write_bytes(original)
        corrupted = bytearray(original)
        wrapped_cms = framework_blobs[0x10000]
        cms_end = original.index(wrapped_cms) + len(wrapped_cms) - 1
        corrupted[cms_end] ^= 1
        framework_binary.write_bytes(corrupted)
        try:
            verify_target(framework_binary, framework, cert, temp, openssl, lab)
        except RuntimeError:
            print('PASS: independent verification rejects CMS tampering.')
        else:
            raise RuntimeError('CMS tampering was not detected')
        finally:
            framework_binary.write_bytes(original)
        print('Synthetic identity is not Apple-authorized. No account, provisioning, iPhone installation or on-device execution has been demonstrated.')
        sentinel.write_text('tampered resource\n')
        try:
            verify_target(root / 'Lab', root, cert, temp, openssl, lab)
        except RuntimeError:
            print('PASS: independent verification rejects tampered resource.')
        else:
            raise RuntimeError('Tampering was not detected')
        result = dict(independentFixtureCryptoVerified=True, independentSwiftCMSVerified=True, targetCount=4, tamperRejected=True, codeTamperRejected=True, cmsTamperRejected=True, nativeCodesignAccepted=native_accepted, nativeVerificationCategory=native_category, nativeRedactedDiagnostic=native_detail, nativeRequirementParsed=requirement_parsed, appleDevelopmentAuthorization=False, physicalDeviceValidated=False, installed=False)
        evidence = pathlib.Path('build-evidence'); evidence.mkdir(exist_ok=True)
        (evidence / 'offline-signing-status.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Our own bounded-stage messages only; never dump subprocess output or secret material.
        print('FAIL: offline signing experiment: ' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
