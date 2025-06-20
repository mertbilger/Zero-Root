import subprocess
import xml.etree.ElementTree as ET
from typing import Optional, Dict

class NmapScanner:
    def __init__(self):
        self.common_ports = "21,22,80,443,3306,3389,8080,8443"

    def run(self, target: str, ports: Optional[str] = None, timeout: int = 300) -> Optional[Dict]:
        ports = ports or self.common_ports

        try:
            print(f"[+] {target} için hızlı port taraması başlatılıyor (Portlar: {ports})...")

            cmd = [
                "nmap",
                "-p", ports,
                "-Pn",
                "-T2",    # Senin Kali çıktısına daha yakın olsun diye -T2 yaptım
                "-n",     # DNS çözümlemeyi kapatır, senin Kali çıktında vardı
                "-sS",
                "-sV",
                "-oX", "-",
                target
            ]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                print(f"[-] Nmap hatası:\n{result.stderr.strip()}")
                return None

            return self._parse_results(result.stdout)

        except subprocess.TimeoutExpired:
            print(f"[-] Tarama zaman aşımına uğradı ({timeout}s)")
            return None
        except Exception as e:
            print(f"[-] Genel hata: {str(e)}")
            return None

    def _parse_results(self, xml_output: str) -> Dict:
        try:
            root = ET.fromstring(xml_output)
            results = {}

            for host in root.findall('host'):
                addr = host.find('address')
                ip = addr.attrib.get('addr') if addr is not None else "Bilinmiyor"

                ports_data = {}
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        portid = port.attrib.get('portid')
                        protocol = port.attrib.get('protocol')
                        state_el = port.find('state')
                        service_el = port.find('service')
                        version_el = port.find('service/version')  # Burada versiyon yok, nmap XML'de version ayrı elemandır.

                        state = state_el.attrib.get('state') if state_el is not None else "unknown"

                        service = service_el.attrib.get('name') if service_el is not None else "unknown"
                        
                        # Nmap XML'de version bilgisi 'service' elementinin içinde genellikle yoktur,
                        # Bunun yerine 'service' elementi içinde "product", "version", "extrainfo" gibi attribute'lar olabilir.
                        # Biz bunları da kontrol edelim:

                        version = ""
                        if service_el is not None:
                            product = service_el.attrib.get('product', '')
                            ver = service_el.attrib.get('version', '')
                            extrainfo = service_el.attrib.get('extrainfo', '')
                            version_parts = [part for part in [product, ver, extrainfo] if part]
                            version = " ".join(version_parts)

                        ports_data[f"{portid}/{protocol}"] = {
                            'state': state,
                            'service': service,
                            'version': version
                        }

                results[ip] = {
                    'ports': ports_data
                }

                # Konsola yazdır
                print(f"\n[+] Hedef: {ip}")
                for port, info in ports_data.items():
                    ver_str = f" - Versiyon: {info['version']}" if info['version'] else ""
                    print(f"  Port {port} - Durum: {info['state']} - Servis: {info['service']}{ver_str}")

            return results

        except ET.ParseError as e:
            print(f"[-] XML parse hatası: {str(e)}")
            return {}
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional, Dict

class NmapScanner:
    def __init__(self):
        self.common_ports = "21,22,80,443,3306,3389,8080,8443"

    def run(self, target: str, ports: Optional[str] = None, timeout: int = 300) -> Optional[Dict]:
        ports = ports or self.common_ports

        try:
            print(f"[+] {target} için hızlı port taraması başlatılıyor (Portlar: {ports})...")

            cmd = [
                "nmap",
                "-p", ports,
                "-Pn",
                "-T2",    # Senin Kali çıktısına daha yakın olsun diye -T2 yaptım
                "-n",     # DNS çözümlemeyi kapatır, senin Kali çıktında vardı
                "-sS",
                "-sV",
                "-oX", "-",
                target
            ]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                print(f"[-] Nmap hatası:\n{result.stderr.strip()}")
                return None

            return self._parse_results(result.stdout)

        except subprocess.TimeoutExpired:
            print(f"[-] Tarama zaman aşımına uğradı ({timeout}s)")
            return None
        except Exception as e:
            print(f"[-] Genel hata: {str(e)}")
            return None

    def _parse_results(self, xml_output: str) -> Dict:
        try:
            root = ET.fromstring(xml_output)
            results = {}

            for host in root.findall('host'):
                addr = host.find('address')
                ip = addr.attrib.get('addr') if addr is not None else "Bilinmiyor"

                ports_data = {}
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        portid = port.attrib.get('portid')
                        protocol = port.attrib.get('protocol')
                        state_el = port.find('state')
                        service_el = port.find('service')
                        version_el = port.find('service/version')  # Burada versiyon yok, nmap XML'de version ayrı elemandır.

                        state = state_el.attrib.get('state') if state_el is not None else "unknown"

                        service = service_el.attrib.get('name') if service_el is not None else "unknown"
                        
                        # Nmap XML'de version bilgisi 'service' elementinin içinde genellikle yoktur,
                        # Bunun yerine 'service' elementi içinde "product", "version", "extrainfo" gibi attribute'lar olabilir.
                        # Biz bunları da kontrol edelim:

                        version = ""
                        if service_el is not None:
                            product = service_el.attrib.get('product', '')
                            ver = service_el.attrib.get('version', '')
                            extrainfo = service_el.attrib.get('extrainfo', '')
                            version_parts = [part for part in [product, ver, extrainfo] if part]
                            version = " ".join(version_parts)

                        ports_data[f"{portid}/{protocol}"] = {
                            'state': state,
                            'service': service,
                            'version': version
                        }

                results[ip] = {
                    'ports': ports_data
                }

                # Konsola yazdır
                print(f"\n[+] Hedef: {ip}")
                for port, info in ports_data.items():
                    ver_str = f" - Versiyon: {info['version']}" if info['version'] else ""
                    print(f"  Port {port} - Durum: {info['state']} - Servis: {info['service']}{ver_str}")

            return results

        except ET.ParseError as e:
            print(f"[-] XML parse hatası: {str(e)}")
            return {}
