import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import subprocess
import socket
import ipaddress
import time
import re
import csv
import winsound
from concurrent.futures import ThreadPoolExecutor

PORTS_TO_SCAN = [20, 21, 22, 23, 80, 443, 445, 3389]

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner Réseau")
        self.root.iconbitmap("scanner.ico")
        self.root.resizable(False, False)

        # Boutons
        button_frame = tk.Frame(root)
        button_frame.pack(pady=(10, 0))

        self.scan_button = tk.Button(button_frame, text="Scan", command=self.manual_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.export_button = tk.Button(button_frame, text="Exporter CSV", command=self.export_csv)
        self.export_button.pack(side=tk.LEFT, padx=5)

        self.html_button = tk.Button(button_frame, text="Exporter HTML", command=self.export_html)
        self.html_button.pack(side=tk.LEFT, padx=5)

        self.sound_button = tk.Button(button_frame, text="Son ON", command=self.toggle_sound)
        self.sound_button.pack(side=tk.LEFT, padx=5)

        # Tableau
        self.tree = ttk.Treeview(root, columns=("ip", "mac", "host", "status", "ports", "os"), show="headings", height=20)
        self.tree.heading("ip", text="Adresse IP")
        self.tree.heading("mac", text="Adresse MAC")
        self.tree.heading("host", text="Nom Machine")
        self.tree.heading("status", text="Statut")
        self.tree.heading("ports", text="Ports Ouverts")
        self.tree.heading("os", text="OS estimé")

        self.tree.column("ip", width=150)
        self.tree.column("mac", width=160)
        self.tree.column("host", width=180)
        self.tree.column("status", width=80)
        self.tree.column("ports", width=200)
        self.tree.column("os", width=100)
        self.tree.pack(padx=5, pady=10)

        # Zone de log
        self.log = scrolledtext.ScrolledText(root, width=100, height=6, fg='white', bg='black')
        self.log.pack(padx=10, pady=(0, 10))
        self.log.insert(tk.END, "[INFO] Scanner démarré...\n")
        self.log.configure(state='disabled')

        self.known_devices = {}
        self.alerts = {}
        self.lock = threading.Lock()
        self.sound_enabled = True

        self.local_ip = self.get_local_ip()
        self.network = ipaddress.ip_network(self.local_ip + '/24', strict=False)

        self.scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        self.scan_thread.start()

    def log_msg(self, message):
        print(message)
        self.log.configure(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.see(tk.END)
        self.log.configure(state='disabled')

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self.log_msg(f"[INFO] IP locale détectée : {ip}")
            return ip
        except Exception as e:
            self.log_msg(f"[ERREUR] IP locale : {e}")
            return "127.0.0.1"

    def toggle_sound(self):
        self.sound_enabled = not self.sound_enabled
        state = "ON" if self.sound_enabled else "OFF"
        self.sound_button.config(text=f"Son {state}")
        self.log_msg(f"[INFO] Alerte sonore : {state}")

    def ping_ip(self, ip):
        try:
            cmd = ['ping', '-n', '1', '-w', '300', ip]
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW  # empêche ouverture de fenêtre CMD
            )
            output = result.stdout
            ttl_match = re.search(r"TTL=(\d+)", output)
            ttl = int(ttl_match.group(1)) if ttl_match else None
            return ("TTL=" in output, ttl)
        except:
            return (False, None)

    def guess_os(self, ttl):
        if ttl is None:
            return "?"
        if ttl >= 128:
            return "Windows"
        elif ttl >= 64:
            return "Linux/Unix"
        elif ttl >= 32:
            return "Routeur/Autre"
        else:
            return "?"

    def get_mac(self, ip):
        try:
            pid = subprocess.Popen(
                ["arp", "-a", ip],
                stdout=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW  # empêche popup
            )
            s = pid.communicate()[0].decode("cp1252", errors="ignore")
            mac = re.search(r"([0-9A-Fa-f]{2}[-:]){5}([0-9A-Fa-f]{2})", s)
            return mac.group(0) if mac else ""
        except:
            return ""

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return ""

    def scan_ports(self, ip):
        open_ports = []
        for port in PORTS_TO_SCAN:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(str(port))
            except:
                continue
        return ', '.join(open_ports)

    def scan_ip(self, ip):
        ip_str = str(ip)
        alive, ttl = self.ping_ip(ip_str)
        if alive:
            mac = self.get_mac(ip_str)
            host = self.get_hostname(ip_str)
            ports = self.scan_ports(ip_str)
            os_guess = self.guess_os(ttl)
            self.log_msg(f"[ACTIF] {ip_str} | MAC: {mac} | Host: {host} | Ports: {ports} | OS: {os_guess}")
            return ip_str, mac, host, "ACTIF", ports, os_guess
        return None

    def scan_network(self):
        self.log_msg("[SCAN] Début du scan réseau (threadé)...")
        results = {}
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = [executor.submit(self.scan_ip, ip) for ip in self.network.hosts()]
            for future in futures:
                result = future.result()
                if result:
                    ip, mac, host, status, ports, os_guess = result
                    results[ip] = (mac, host, status, ports, os_guess)
        self.log_msg("[SCAN] Scan terminé.")
        return results

    def display_devices(self, devices):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for ip, (mac, host, status, ports, os_guess) in devices.items():
            tag = "alert" if ip in self.alerts else ""
            self.tree.insert("", "end", values=(ip, mac, host, status, ports, os_guess), tags=(tag,))
        self.tree.tag_configure("alert", background="red", foreground="white")

    def scan_and_display(self):
        current_devices = self.scan_network()
        with self.lock:
            new_ips = set(current_devices) - set(self.known_devices)
            for ip in new_ips:
                self.alerts[ip] = time.time()
                self.log_msg(f"[ALERTE] Nouvelle IP détectée : {ip}")
                if self.sound_enabled:
                    winsound.Beep(1000, 500)
            now = time.time()
            self.alerts = {ip: t for ip, t in self.alerts.items() if now - t < 60}
            self.known_devices = current_devices.copy()
        self.root.after(0, self.display_devices, current_devices)

    def manual_scan(self):
        self.log_msg("[MANUEL] Scan manuel demandé.")
        threading.Thread(target=self.scan_and_display, daemon=True).start()

    def export_csv(self):
        try:
            filename = f"scan_{time.strftime('%Y%m%d_%H%M%S')}.csv"
            with open(filename, mode='w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Adresse IP", "Adresse MAC", "Nom Machine", "Statut", "Ports Ouverts", "OS"])
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item)['values'])
            self.log_msg(f"[EXPORT] Résultats exportés dans : {filename}")
        except Exception as e:
            self.log_msg(f"[ERREUR] Export CSV : {e}")

    def export_html(self):
        try:
            filename = f"scan_{time.strftime('%Y%m%d_%H%M%S')}.html"
            with open(filename, mode='w', encoding='utf-8') as f:
                f.write("<html><head><title>Scan Réseau</title></head><body>")
                f.write("<h2>Résultats du scan réseau</h2>")
                f.write("<table border='1' cellspacing='0' cellpadding='5'>")
                f.write("<tr><th>Adresse IP</th><th>MAC</th><th>Nom</th><th>Statut</th><th>Ports</th><th>OS</th></tr>")
                for item in self.tree.get_children():
                    row = self.tree.item(item)['values']
                    f.write("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
                f.write("</table></body></html>")
            self.log_msg(f"[EXPORT] Résultats HTML : {filename}")
        except Exception as e:
            self.log_msg(f"[ERREUR] Export HTML : {e}")

    def scan_loop(self):
        while True:
            self.scan_and_display()
            time.sleep(60)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
