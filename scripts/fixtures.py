"""Synthetic disposable ZIP fixtures; no owner applications or credentials."""
import plistlib, zipfile, pathlib, struct
root = pathlib.Path(__file__).resolve().parents[1] / 'Tests/OmniCoreTests/Fixtures'
root.mkdir(parents=True, exist_ok=True)
def info(identifier, exe):
    return plistlib.dumps(dict(CFBundleIdentifier=identifier, CFBundleExecutable=exe, CFBundleName=exe, CFBundleVersion='2', CFBundleShortVersionString='1.2'), fmt=plistlib.FMT_BINARY)
header = bytes.fromhex('cffaedfe') + bytes(60)
base = {'Payload/Test.app/Info.plist':info('org.omnisign.disposable','Test'), 'Payload/Test.app/Test':header,
'Payload/Test.app/Frameworks/Lib.framework/Info.plist':info('org.omnisign.lib','Lib'), 'Payload/Test.app/Frameworks/Lib.framework/Lib':header,
'Payload/Test.app/PlugIns/Widget.appex/Info.plist':info('org.omnisign.disposable.widget','Widget'), 'Payload/Test.app/PlugIns/Widget.appex/Widget':header,
'Payload/Test.app/Frameworks/libtest.dylib':header}
def write(name, entries):
    with zipfile.ZipFile(root / (name+'.ipa'),'w', compression=zipfile.ZIP_DEFLATED) as z:
        for k,v in entries.items(): z.writestr(k,v)
write('valid',base)
write('missingframework', {k:v for k,v in base.items() if k!='Payload/Test.app/Frameworks/Lib.framework/Info.plist'})
for name,path in [('traversal','../outside'),('absolute','/tmp/outside'),('backslash','Payload\\bad'),('collision','payload/test.app/test')]: write(name,base|{path:b'bad'})
write('missing', {k:v for k,v in base.items() if k!='Payload/Test.app/Test'})
write('badmagic',base|{'Payload/Test.app/Test':bytes(64)})
write('multiple',base|{'Payload/Other.app/Info.plist':info('org.other','Other')})
with zipfile.ZipFile(root/'symlink.ipa','w') as z:
    for k,v in base.items(): z.writestr(k,v)
    e=zipfile.ZipInfo('Payload/Test.app/link');e.create_system=3;e.external_attr=(0o120777 << 16);z.writestr(e,'../../outside')
# Stored member whose bytes are changed without updating central-directory CRC.
with zipfile.ZipFile(root/'corrupt.ipa','w') as z:
    for k,v in base.items():z.writestr(k,v)
p=root/'corrupt.ipa'; b=bytearray(p.read_bytes()); i=b.index(header);b[i+10]^=1;p.write_bytes(b)

# Reject an entry exceeding the declared per-member expanded limit without allocating it.
p=root/'oversize.ipa';b=bytearray((root/'valid.ipa').read_bytes());i=b.index(b'PK\x01\x02');struct.pack_into('<I',b,i+24,600_000_000);p.write_bytes(b)
