"""Select an available iPhone simulator; report the runtime separately in build logs."""
import json
import subprocess
import sys
result = json.loads(subprocess.check_output(['xcrun', 'simctl', 'list', 'devices', 'available', '--json']))
phones = [(runtime, device) for runtime, devices in result['devices'].items() if 'iOS' in runtime for device in devices if device.get('isAvailable') and device['name'].startswith('iPhone')]
if not phones:
    raise SystemExit('No available iPhone Simulator runtime on this runner')
phones.sort(key=lambda pair: ('iPhone 17' in pair[1]['name'], pair[0], pair[1]['name']), reverse=True)
runtime, device = phones[0]
print(f"Simulator smoke test uses {device['name']} / {runtime}; this is not physical-device acceptance.", file=sys.stderr)
print(device['udid'])
