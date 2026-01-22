# router-intel
This is a Local router intel tool. When helping someone with their home network, collect infomration about the router.

WARNING Only for use with persmission on the network. The script checks ssh for default credentials.

Requirements:
- `pip install paramiko scapy requests pysnmp`

To turn [router_discover.py](router_discover.py) into an .exe file:

1. Install pyinstaller
    - `pip install pyinstaller`
2. Package
    - because the script uses Scapy, which often requires administrative privileges to sniff packets or perform ARP lookups, use the `--uad-admin` flag
    - `python -m PyInstaller --onefile --uac-admin --name "RouterAudit" .\router_discovery.py`
    - look for the completed `RouterAudit.exe` in the `dist` folder

BONUS: Add an icon file
1. Get an `icon.ico file` and save it in the same directory
2. Add the `--icon` flag to the build command
    - Ex. `python -m PyInstaller --onefile --uac-admin --icon="icon.ico" --name "RouterAudit" .\router_discovery.py`
  
BONUS: Compress the size with UPX
1. Download UPX from the [UPX GitHub Releases page](https://github.com/upx/upx/releases)
    - Windows 64-bit: e.g., upx-4.2.2-win64.zip
2. Extract the ZIP file. You only need the upx.exe file.
3. Place the upx.exe file directly into the same folder
4. Add the `--upx-dir` flag to your build command
    - Ex. `python -m PyInstaller --onefile --uac-admin --upx-dir="." --icon="icon.ico" --name "RouterAudit" .\router_discovery.py`
