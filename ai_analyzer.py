from typing import Dict, List
from datetime import datetime

class VulnerabilityAnalyzer:
    def __init__(self):
        self.expert_rules = self._load_rules()
        self.huggingface_api = "https://api-inference.huggingface.co/models/distilbert-base-uncased"

    def _load_rules(self) -> Dict:
        return {
            # SSL/TLS Kuralları
            'ssl_v2_vuln': {
                'condition': lambda x: x.get('ssl_tests', {}).get('SSLv2_support', {}).get('status') == 'VULNERABLE',
                'recommendation': 'SSLv2 desteği derhal kapatılmalıdır (CVE-2011-3389). Minimum TLS 1.2 kullanın.',
                'severity': 'CRITICAL',
                'category': 'SSL/TLS'
            },
            'tls_1.0_enabled': {
                # Burada status VULNERABLE veya ENABLED olabilir, örnek veriyorum:
                'condition': lambda x: x.get('ssl_tests', {}).get('TLSv1_support', {}).get('status') == 'VULNERABLE',
                'recommendation': 'TLS 1.0 BEAST saldırılarına açıktır. TLS 1.2 veya 1.3 kullanın.',
                'severity': 'HIGH',
                'category': 'SSL/TLS'
            },
            'cert_expiry_soon': {
                'condition': lambda x: (
                    'certificate_expiry' in x.get('ssl_tests', {}) and
                    'days' in x['ssl_tests']['certificate_expiry']['value'] and
                    int(''.join(filter(str.isdigit, x['ssl_tests']['certificate_expiry']['value']))) < 15
                ),
                'recommendation': 'SSL sertifikası 15 gün içinde sona erecek. Acilen yenilenmeli.',
                'severity': 'HIGH',
                'category': 'SSL/TLS'
            },

            # HTTP Header Kuralı - Yeni Ekleme
            'http_strict_transport_security_missing': {
                'condition': lambda x: 'http_headers' in x and not any(
                    header.lower() == 'strict-transport-security'
                    for header in x['http_headers'].keys()
                ),
                'recommendation': 'HTTP Strict Transport Security (HSTS) header eksik. Eklenmesi önerilir.',
                'severity': 'MEDIUM',
                'category': 'HTTP'
            },

            # Nmap Tarama Kuralları
            'ftp_anonymous': {
                'condition': lambda x: any(
                    port.get('service', '').lower() == 'ftp' and 'Anonymous' in port.get('version', '')
                    for host in x.get('nmap', {}).values()
                    for port in host.get('ports', {}).values()
                ),
                'recommendation': 'FTP sunucusunda anonymous girişe izin veriliyor. Derhal kapatın.',
                'severity': 'CRITICAL',
                'category': 'Port'
            },
            'telnet_enabled': {
                'condition': lambda x: any(
                    port.get('service', '').lower() == 'telnet'
                    for host in x.get('nmap', {}).values()
                    for port in host.get('ports', {}).values()
                ),
                'recommendation': 'Telnet servisi aktif (şifrelenmemiş trafik). SSH kullanın.',
                'severity': 'HIGH',
                'category': 'Port'
            },
            'rdp_exposed': {
                'condition': lambda x: any(
                    port.get('port', '') in ['3389', '3388'] and port.get('state', '') == 'open'
                    for host in x.get('nmap', {}).values()
                    for port in host.get('ports', {}).values()
                ),
                'recommendation': 'RDP portu (3389) internete açık. Ağ seviyesinde kısıtlayın veya VPN kullanın.',
                'severity': 'HIGH',
                'category': 'Port'
            },

            # DNS Kuralları
            'dns_zone_transfer': {
                'condition': lambda x: any(
                    'AXFR' in record for records in x.get('dns_records', {}).values()
                    for record in records
                ),
                'recommendation': 'DNS zone transfer (AXFR) açık. BIND ayarlarını gözden geçirin.',
                'severity': 'MEDIUM',
                'category': 'DNS'
            },
            'spf_missing': {
                'condition': lambda x: not any(
                    'v=spf1' in record for record in x.get('dns_records', {}).get('TXT', [])
                ),
                'recommendation': 'SPF kaydı eksik. E-posta spoofing saldırılarına açık.',
                'severity': 'MEDIUM',
                'category': 'DNS'
            },

            # Whois Kuralları
            'domain_expiry_soon': {
                'condition': lambda x: (
                    'whois' in x and 
                    'Expiration Date' in x['whois'] and
                    (datetime.strptime(x['whois']['Expiration Date'], '%Y-%m-%d %H:%M:%S') - datetime.now()).days < 30
                ),
                'recommendation': 'Domain 30 gün içinde sona erecek. Yenileme yapılmalı.',
                'severity': 'MEDIUM',
                'category': 'Domain'
            },
            'registrar_abuse': {
                'condition': lambda x: 'whois' in x and any(
                    bad_registrar in x['whois'].get('Registrar', '').lower() 
                    for bad_registrar in ['godaddy', 'namecheap']
                ),
                'recommendation': 'Şüpheli domain kayıt şirketi. Transfer önerilir.',
                'severity': 'LOW',
                'category': 'Domain'
            },

            # Wayback Machine Kuralları
            'exposed_backup_files': {
                'condition': lambda x: any(
                    '.bak' in record['url'] or 'backup' in record['url'].lower()
                    for record in x.get('wayback_data', [])
                ),
                'recommendation': 'Yedek dosyalar web arşivlerinde tespit edildi. Temizlenmeli.',
                'severity': 'MEDIUM',
                'category': 'Web'
            },
            'old_php_versions': {
                'condition': lambda x: any(
                    'php/5.' in record['url'] or 'php4' in record['url']
                    for record in x.get('wayback_data', [])
                ),
                'recommendation': 'Eski PHP versiyonları tespit edildi (CVE-2019-11043 gibi).',
                'severity': 'HIGH',
                'category': 'Web'
            }
        }

    def _generate_ai_insights(self, data: Dict) -> List[str]:
        """Tüm veri setini analiz eden AI yorumları"""
        insights = []

        # Port analizi
        open_ports = sum(len(host.get('ports', {})) for host in data.get('nmap', {}).values())
        if open_ports > 20:
            insights.append(f"Çok fazla açık port ({open_ports}). Gereksiz servisler kapatılmalı.")

        # SSL analizi
        if 'ssl_tests' in data:
            weak_ciphers = sum(1 for test in data['ssl_tests'].values() if test.get('status') == 'VULNERABLE')
            if weak_ciphers > 0:
                insights.append(f"{weak_ciphers} zayıf şifreleme protokolü tespit edildi.")

            # Ek: Sertifika geçerlilik süresi kontrolü
            try:
                cert_expiry_str = data['ssl_tests'].get('certificate_expiry', {}).get('value', '')
                if cert_expiry_str:
                    days_left = int(''.join(filter(str.isdigit, cert_expiry_str)))
                    if days_left < 0:
                        insights.append("SSL sertifikası süresi dolmuş.")
            except Exception:
                pass

        # DNS analizi
        if 'dns_records' in data:
            if not any('DMARC' in record for record in data['dns_records'].get('TXT', [])):
                insights.append("DMARC kaydı eksik - E-posta güvenliği zayıf")

        return insights if insights else ["Temel güvenlik kontrolleri başarılı görünüyor"]

    def analyze(self, scan_data: Dict) -> Dict:
        """Tüm veriyi analiz edip konsol ve rapor çıktısı üretir"""
        matched_rules = []
        for rule_name, rule in self.expert_rules.items():
            try:
                if rule['condition'](scan_data):
                    matched_rules.append({'id': rule_name, **rule})
            except Exception:
                # Hata varsa kural atlanır
                continue
        
        ai_insights = self._generate_ai_insights(scan_data)

        return {
            'rule_based': matched_rules,
            'ai_insights': ai_insights,
            'summary_stats': {
                'critical': sum(1 for r in matched_rules if r['severity'] == 'CRITICAL'),
                'high': sum(1 for r in matched_rules if r['severity'] == 'HIGH'),
                'total_vulns': len(matched_rules)
            }
        }
