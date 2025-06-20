import socket
import ssl
from datetime import datetime
import requests
from socket import socket as socket_object
import concurrent.futures
from typing import Dict, Any

class SSLTester:
    @staticmethod
    def run(domain: str) -> Dict[str, Any]:
        """
        Hedef domain için kapsamlı SSL/TLS testleri yürütür
        
        Args:
            domain: Test edilecek domain adı
            
        Returns:
            Test sonuçlarını içeren sözlük
        """
        try:
            print(f"\n[+] SSL/TLS testleri başlatılıyor: {domain}")
            
            # Temel bağlantı ve sertifika bilgileri
            cert_info = SSLTester._get_certificate_info(domain)
            if not cert_info:
                return {'error': 'Temel sertifika bilgileri alınamadı'}
                
            results = SSLTester._process_certificate_info(cert_info)
            
            # Ek testleri ayrı bir thread'de çalıştır
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(SSLTester._run_additional_tests, domain)
                try:
                    additional_results = future.result(timeout=60)  # 60 saniye timeout
                    results.update(additional_results)
                except concurrent.futures.TimeoutError:
                    print("[-] Ek testler zaman aşımına uğradı (60 saniye)")
                    results['error'] = 'Ek testler zaman aşımına uğradı'
            
            return results
            
        except Exception as e:
            print(f"[-] SSL test hatası: {e}")
            return {'error': str(e)}

    @staticmethod
    def _get_certificate_info(domain: str) -> Dict:
        """Sunucudan sertifika bilgilerini alır"""
        try:
            context = ssl.create_default_context()
            context.timeout = 10  # Bağlantı timeout'u
            
            with socket_object() as sock:
                sock.settimeout(10)
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.connect((domain, 443))
                    return ssock.getpeercert()
        except Exception as e:
            print(f"[-] Sertifika bilgisi alınamadı: {e}")
            return {}

    @staticmethod
    def _process_certificate_info(cert: Dict) -> Dict[str, Any]:
        """Sertifika bilgilerini işler ve sonuçları döndürür"""
        print("\n[+] Sertifika Bilgileri:")
        
        if not cert:
            return {}
            
        try:
            expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expire_date - datetime.now()).days
            
            results = {
                'certificate_expiry': {
                    'value': f"{expire_date} ({days_left} gün kaldı)",
                    'status': 'WARNING' if days_left < 30 else 'SECURE'
                },
                'tls_version': {
                    'value': 'Unknown',
                    'status': 'UNKNOWN'
                },
                'certificate_issuer': {
                    'value': dict(x[0] for x in cert['issuer']),
                    'status': 'INFO'
                },
                'certificate_subject': {
                    'value': dict(x[0] for x in cert['subject']),
                    'status': 'INFO'
                }
            }
            
            for k, v in results.items():
                print(f"{k.upper().replace('_', ' ')}: {v['value']}")
                
            return results
            
        except Exception as e:
            print(f"[-] Sertifika işleme hatası: {e}")
            return {}

    @staticmethod
    def _run_additional_tests(domain: str) -> Dict[str, Any]:
        """Ek SSL/TLS testlerini yürütür"""
        print("\n[+] Ek SSL/TLS Testleri:")
        
        results = {}
        
        # TLS versiyon testleri
        tls_results = SSLTester._test_tls_versions(domain)
        results.update(tls_results)
        
        # HSTS testi
        hsts = SSLTester._check_hsts(domain)
        results['hsts_enabled'] = {
            'value': str(hsts),
            'status': 'SECURE' if hsts else 'WARNING'
        }
        
        # Heartbleed testi (timeout'lu)
        try:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(SSLTester._check_heartbleed, domain)
                heartbleed = future.result(timeout=15)  # 15 saniye timeout
                
                results['heartbleed_vulnerable'] = {
                    'value': str(heartbleed),
                    'status': 'VULNERABLE' if heartbleed else 'SECURE'
                }
        except concurrent.futures.TimeoutError:
            print("[-] Heartbleed testi zaman aşımına uğradı (15 saniye)")
            results['heartbleed_test'] = {
                'value': 'Timeout',
                'status': 'ERROR'
            }
        
        return results

    @staticmethod
    def _test_tls_versions(domain: str) -> Dict[str, Any]:
        """Desteklenen TLS versiyonlarını test eder"""
        tls_versions = {
            'TLSv1': getattr(ssl, 'PROTOCOL_TLSv1', None),
            'TLSv1.1': getattr(ssl, 'PROTOCOL_TLSv1_1', None),
            'TLSv1.2': getattr(ssl, 'PROTOCOL_TLSv1_2', None),
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLS', None)
        }
        
        results = {}
        
        for name, proto in tls_versions.items():
            if proto is None:
                print(f"{name}: Sistemde desteklenmiyor.")
                results[f'{name}_support'] = {
                    'value': 'Not available',
                    'status': 'INFO'
                }
                continue
    
            try:
                print(f"[*] {name} desteği kontrol ediliyor...")
                context = ssl.SSLContext(proto)
                context.timeout = 5
                
                with socket_object() as sock:
                    sock.settimeout(5)
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        ssock.connect((domain, 443))
    
                results[f'{name}_support'] = {
                    'value': 'Supported',
                    'status': 'SECURE'
                }
                print(f"{name}: ✅ Supported")
            except Exception as e:
                results[f'{name}_support'] = {
                    'value': 'Not supported',
                    'status': 'WARNING'
                }
                print(f"{name}: ⚠️ Not supported ({str(e)})")
        
        return results

    @staticmethod
    def _check_hsts(domain: str) -> bool:
        """HSTS desteğini kontrol eder"""
        print("[*] HSTS kontrolü yapılıyor...")
        try:
            response = requests.get(
                f"https://{domain}", 
                timeout=5,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            return 'strict-transport-security' in response.headers
        except Exception as e:
            print(f"[-] HSTS kontrol hatası: {e}")
            return False

    @staticmethod
    def _check_heartbleed(domain: str) -> bool:
        """Heartbleed zafiyetini kontrol eder"""
        print("[*] Heartbleed zafiyeti kontrol ediliyor...")
        try:
            context = ssl.create_default_context()
            context.timeout = 10
            
            with socket_object() as sock:
                sock.settimeout(10)
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.connect((domain, 443))
                    ssock.send(bytes.fromhex('01010101'))  # Heartbleed payload
                    response = ssock.recv(1024)
                    return len(response) > 0
        except Exception as e:
            print(f"[-] Heartbleed test hatası: {e}")
            return False