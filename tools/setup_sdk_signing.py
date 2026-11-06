"""Extract pinned portable Microsoft SDK signing tools; no system installation."""
import hashlib
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = '10.0.26100.6584'
NAME = 'microsoft.windows.sdk.buildtools.' + VERSION + '.nupkg'
URL = 'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/' + VERSION + '/' + NAME
SHA512 = '38503c70afde3dc89fccca69d13b78b8f38a50e063e7f90a6362003652e375a1b32dafb9ef18a5d045195f77310a85d4ade749cf015f4145d0c175aeb054405b'
FILES = ['signtool.exe', 'signtool.exe.manifest', 'mssign32.dll', 'wintrust.dll', 'wintrust.dll.ini',
         'Microsoft.Windows.Build.Signing.mssign32.dll.manifest',
         'Microsoft.Windows.Build.Signing.wintrust.dll.manifest',
         'appxsip.dll', 'appxpackaging.dll', 'opcservices.dll',
         'Microsoft.Windows.Build.Appx.AppxSip.dll.manifest',
         'Microsoft.Windows.Build.Appx.AppxPackaging.dll.manifest',
         'Microsoft.Windows.Build.Appx.OpcServices.dll.manifest']


def setup():
    archive = ROOT / '.tools' / NAME
    archive.parent.mkdir(exist_ok=True)
    if not archive.exists():
        urllib.request.urlretrieve(URL, archive)
    if hashlib.sha512(archive.read_bytes()).hexdigest() != SHA512:
        raise ValueError('SDK archive SHA512 mismatch; refusing extraction')
    output = ROOT / '.tools' / ('sdk-signing-' + VERSION)
    with zipfile.ZipFile(archive) as package:
        files = {name: package.read('bin/10.0.26100.0/x64/' + name) for name in FILES}
        files['Microsoft.Windows.SDK.BuildTools.nuspec'] = package.read('Microsoft.Windows.SDK.BuildTools.nuspec')
    for name, data in files.items():
        target = output / name
        if target.exists() and target.read_bytes() != data:
            raise ValueError('Refusing differing existing SDK file: ' + name)
    output.mkdir(exist_ok=True)
    for name, data in files.items():
        if not (output / name).exists():
            (output / name).write_bytes(data)
    print(output)


if __name__ == '__main__':
    setup()
