"""
detect home router
pip install paramiko scapy requests pysnmp
"""
import scapy.all as scapy
import requests
import socket
import re
import urllib3
import os
import paramiko

# Global Silencer
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
scapy.conf.verb = 0 

class RouterIntelPro:
    def __init__(self):
        self.gateway_ip = "192.168.99.254" 
        self.clues = []
        self.management_url = None
        self.ssh_creds = [
            ('admin', 'pfsense'), ('root', 'pfsense'),
            ('admin', 'admin'), ('admin', 'password'),
            ('root', 'root'), ('ubnt', 'ubnt')
        ]
        self.fingerprints = {
            "pfSense/Netgate": ["pfsense", "netgate", "nginx", "freebsd"],
            "ASUS": ["asus", "rt-ac", "rt-ax", "merlin", "asuswrt", "httpd"],
            "TP-Link": ["tp-link", "tplink", "archer", "tether", "uhttpd"],
            "Netgear": ["netgear", "nighthawk", "genie", "httpd"],
            "Ubiquiti": ["ubnt", "unifi", "edgeos", "microhttpd"],
            "Linksys": ["linksys", "velop", "smart wi-fi"]
        }

    def log_clue(self, source, data, weight):
        if data:
            self.clues.append({"source": source, "data": str(data).strip(), "weight": weight})

    def check_captive_portal(self):
        """Detects if the router is intercepting traffic and captures the portal URL"""
        check_urls = ["http://connectivitycheck.gstatic.com/generate_204"]
        for url in check_urls:
            try:
                r = requests.get(url, timeout=3, allow_redirects=False)
                if 300 <= r.status_code < 400:
                    target = r.headers.get('Location', 'Unknown')
                    self.log_clue("Captive Portal", f"DETECTED (Redirect to: {target})", 80)
                    return True
            except: continue
        return False

    def get_hardware_intel(self):
        mac = scapy.getmacbyip(self.gateway_ip)
        if not mac:
            with os.popen(f"arp -a {self.gateway_ip}") as f:
                output = f.read()
                match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", output)
                mac = match.group(0).replace('-', ':').upper() if match else "Unknown"
        
        prefix = mac[:8].upper()
        if prefix == "40:62:31": vendor = "Intel (Custom/Whitebox)"
        elif prefix in ["00:08:A2", "90:EC:77"]: vendor = "Netgate Appliance"
        else: vendor = "Third-Party/Generic"
        self.log_clue("Hardware", f"{vendor} ({mac})", 40)

    def scan_web(self):
        found_proto = []
        for proto in ["https", "http"]: # Priority to HTTPS
            try:
                r = requests.get(f"{proto}://{self.gateway_ip}", timeout=3, verify=False)
                found_proto.append(proto)
                server = r.headers.get("Server", "")
                if server: self.log_clue(f"{proto.upper()} Server", server, 40)
                
                title_search = re.search('(?<=<title>).+?(?=</title>)', r.text, re.I)
                if title_search:
                    self.log_clue(f"{proto.upper()} Title", title_search.group(0).strip(), 60)
                
                if "pfsense" in r.text.lower():
                    self.log_clue("Web Content", f"Found pfSense keywords in {proto.upper()}", 50)
            except: continue
        
        # Set the management URL based on availability
        if "https" in found_proto:
            self.management_url = f"https://{self.gateway_ip}"
        elif "http" in found_proto:
            self.management_url = f"http://{self.gateway_ip}"

    def scan_services(self):
        ports = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS"}
        ssh_active = False
        open_list = []
        for p, n in ports.items():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((self.gateway_ip, p)) == 0:
                    open_list.append(f"{p}({n})")
                    if p == 22: ssh_active = True
        
        if open_list: self.log_clue("Open Ports", ", ".join(open_list), 20)
        
        # If standard ports are closed, check for common alt web port
        if not self.management_url:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((self.gateway_ip, 8080)) == 0:
                    self.management_url = f"http://{self.gateway_ip}:8080"
                    self.log_clue("Open Ports", "8080(HTTP-Alt)", 20)

        if ssh_active: 
            try:
                # Basic login check for the report
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                for user, pw in self.ssh_creds:
                    try:
                        client.connect(self.gateway_ip, username=user, password=pw, timeout=2)
                        self.log_clue("SSH Auth", f"SUCCESS ({user}:{pw})", 100)
                        client.close()
                        break
                    except: continue
            except: pass

    def run(self):
        print(f"[*] Auditing Gateway: {self.gateway_ip}...")
        self.get_hardware_intel()
        self.check_captive_portal()
        
        try:
            name, _, _ = socket.gethostbyaddr(self.gateway_ip)
            self.log_clue("DNS Hostname", name, 60)
        except: pass
        
        self.scan_web()
        self.scan_services()

        # Scoring
        scores = {v: 0 for v in self.fingerprints}
        for clue in self.clues:
            val = str(clue['data']).lower()
            for v, keywords in self.fingerprints.items():
                if any(k in val for k in keywords): scores[v] += clue['weight']

        print("\n" + "="*60 + "\nROUTER INTELLIGENCE REPORT\n" + "="*60)
        for clue in self.clues:
            print(f" [+] {clue['source']:14}: {clue['data']}")
        
        if self.management_url:
            print(f" [+] WEB INTERFACE : {self.management_url}")

        print("\n[Confidence Assessment]")
        results = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        for v, s in results:
            if s > 0:
                print(f" >> {v:18} | {min(100.0, (s / 150.0) * 100.0):.1f}% Confidence")

if __name__ == "__main__":
    RouterIntelPro().run()
