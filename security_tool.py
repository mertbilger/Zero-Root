import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import socket
from socket import socket as socket_object
import requests
import dns.resolver
import whois
import concurrent.futures
import nmap
from urllib.parse import urlparse, urljoin
import ssl
from datetime import datetime
import json
import os
from bs4 import BeautifulSoup
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template
from io import BytesIO
import base64
from ai_analyzer import VulnerabilityAnalyzer
from modules.dns_lookup import DNSLookup
from modules.ssl_tester import SSLTester
from modules.nmap_scanner import NmapScanner
from modules.whois_lookup import WhoisLookup
from modules.wayback_machine import WaybackMachine
from modules.report_generator import ReportGenerator
from modules.badusb_generator import BadUSBGenerator


class SecurityTool:
    def __init__(self):
        self.target_url = None
        self.target_ip = None
        self.analyzer = VulnerabilityAnalyzer()
        self.target_domain = None
        self.session = requests.Session()
        self.ssl_test_results = {}
        self.ascii_art = r"""
         .--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--. 
        / .. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \
        \ \/\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ \/ /
         \/ /`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'\/ / 
        / /\                                                                            / /\ 
        / /\ \       ___           ___           ___           ___           ___        / /\ \
        \ \/ /      /\__\         /\__\         /\  \         /\  \         /\  \       \ \/ / 
         \/ /      /::|  |       /:/ _/_       /::\  \       /::\  \       /::\  \       \/ / 
        / /\     /:/:|  |      /:/ /\__\     /:/\:\__\     /:/\:\  \     /:/\:\__\      / /\ 
        / /\ \   /:/|:|  |__   /:/ /:/ _/_   /:/ /:/  /    /:/  \:\  \   /:/ /:/  /     / /\ \
        \ \/ /  /:/ |:| /\__\ /:/_/:/ /\__\ /:/_/:/__/___ /:/__/ \:\__\ /:/_/:/__/___   \ \/ /
         \/ /   \/__|:|/:/  / \:\/:/ /:/  / \:\/:::::/  / \:\  \ /:/  / \:\/:::::/  /    \/ / 
        / /\       |:/:/  /   \::/_/:/  /   \::/~~/~~~~   \:\  /:/  /   \::/~~/~~~~     / /\ 
        / /\ \      |::/  /     \:\/:/  /     \:\~~\        \:\/:/  /     \:\~~\        / /\ \
        \ \/ /      |:/  /       \::/  /       \:\__\        \::/  /       \:\__\       \ \/ /
         \/ /       |/__/         \/__/         \/__/         \/__/         \/__/        \/ / 
        / /\        ___           ___                                                   / /\ 
        / /\ \      /\  \         /\  \                                                 / /\ \
        \ \/ /     /::\  \       /::\  \         ___                                    \ \/ /
         \/ /     /:/\:\  \     /:/\:\  \       /\__\                                    \/ / 
        / /\    /:/  \:\  \   /:/  \:\  \     /:/  /                                    / /\ 
        / /\ \  /:/__/ \:\__\ /:/__/ \:\__\   /:/__/                                    / /\ \
        \ \/ /  \:\  \ /:/  / \:\  \ /:/  /  /::\  \                                    \ \/ /
         \/ /    \:\  /:/  /   \:\  /:/  /  /:/\:\  \                                    \/ / 
        / /\     \:\/:/  /     \:\/:/  /   \/__\:\  \                                   / /\ 
        / /\ \     \::/  /       \::/  /         \:\__\                                 / /\ \
        \ \/ /      \/__/         \/__/           \/__/                                 \ \/ /
         \/ /                                                                            \/ / 
        / /\.--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--..--./ /\ 
        / /\ \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \.. \/\ \
        \ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `'\ `' /
        `--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'`--'--'--
        .--.       .--.
            _  `    \     /    `  _
             `\.===. \.^./ .===./`
                    \/`"`\/
                ,  | y2k |  ,
                / `\|;-.-'|/` \
                /    |::\  |    \
            .-' ,-'`|:::; |`'-, '-.
                |   |::::\|   | 
                |   |::::;|   |
                |   \:::://   |
                |    `.://'   |
        jgs    .'             `.
            _,'                 `,_    
                """
        
        self.report_data = {
            'target': {},
            'ssl_tests': {},
            'wayback_data': [],
            'dns_records': {},
            'whois': {},
            'nmap': {}
        }
        
        self.html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        .container { max-width: 1200px; margin: auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
        .section-title { color: #2c3e50; border-bottom: 2px solid #2c3e50; padding-bottom: 10px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .vulnerable { color: #e74c3c; font-weight: bold; }
        .secure { color: #27ae60; }
        .warning { color: #f39c12; }
        .chart { margin-top: 20px; text-align: center; }
        .footer { margin-top: 30px; text-align: center; font-size: 0.9em; color: #7f8c8d; }
        .risk-summary { display: flex; justify-content: space-around; margin: 20px 0; gap: 10px; flex-wrap: wrap; }
        .risk-level { padding: 12px 25px; border-radius: 5px; font-weight: bold; font-size: 1.1em; min-width: 100px; text-align: center; }
        .risk-level.critical { background-color: #e74c3c; color: white; }
        .risk-level.high { background-color: #f39c12; color: white; }
        .risk-level.total { background-color: #3498db; color: white; }
        .findings { list-style-type: none; padding: 0; margin-top: 15px; }
        .findings li { padding: 15px; margin-bottom: 15px; border-left: 6px solid; border-radius: 4px; background-color: #fff; box-shadow: 0 1px 3px rgb(0 0 0 / 0.1); }
        .findings li.critical { border-color: #e74c3c; background-color: #fdecea; }
        .findings li.high { border-color: #f39c12; background-color: #fef5e7; }
        .findings strong { font-weight: 700; }
        .findings small { color: #555; font-style: italic; display: block; margin-top: 5px; }
        .ai-recommendations { background-color: #f8f9fa; padding: 20px; border-radius: 5px; font-size: 1em; line-height: 1.5; }
        .ai-recommendations p { margin: 0 0 10px; }
        a { color: #2980b9; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <h2>{{ target }}</h2>
            <p>Generated on {{ date }}</p>
        </div>

        <div class="section" id="summary">
            <h3 class="section-title">Scan Summary</h3>
            <table>
                <tr><th>Target URL</th><td>{{ target_url }}</td></tr>
                <tr><th>IP Address</th><td>{{ target_ip }}</td></tr>
                <tr><th>Scan Date</th><td>{{ date }}</td></tr>
            </table>
        </div>

        {% if ssl_tests %}
        <div class="section" id="ssl-tests">
            <h3 class="section-title">6. SSL/TLS Testleri</h3>
            <table>
                <tr><th>Test</th><th>Result</th><th>Status</th></tr>
                {% for test, result in ssl_tests.items() %}
                <tr>
                    <td>{{ test }}</td>
                    <td>{{ result.value }}</td>
                    <td class="{% if result.status == 'VULNERABLE' %}vulnerable{% elif result.status == 'WARNING' %}warning{% else %}secure{% endif %}">
                        {{ result.status }}
                    </td>
                </tr>
                {% endfor %}
            </table>
            
            <div class="chart">
                <h4>Certificate Validity Timeline</h4>
                <img src="data:image/png;base64,{{ cert_chart }}" alt="Certificate Validity Chart">
            </div>
        </div>
        {% endif %}

        {% if wayback_data %}
        <div class="section" id="wayback">
            <h3 class="section-title">7. Wayback Machine Taraması</h3>
            <p>Found {{ wayback_data|length }} historical records</p>
            <table>
                <tr><th>Date</th><th>URL</th><th>Status Code</th></tr>
                {% for record in wayback_data %}
                <tr>
                    <td>{{ record.timestamp }}</td>
                    <td><a href="{{ record.url }}" target="_blank">{{ record.url }}</a></td>
                    <td>{{ record.status_code }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if ai_analysis %}
        <div class="section" id="ai-analysis">
            <h3 class="section-title">8. 🔍 AI Güvenlik Analizi</h3>
            
            <div class="risk-summary">
                <div class="risk-level critical">
                    CRITICAL: {{ ai_analysis.summary_stats.critical }}
                </div>
                <div class="risk-level high">
                    HIGH: {{ ai_analysis.summary_stats.high }}
                </div>
                <div class="risk-level total">
                    TOTAL: {{ ai_analysis.summary_stats.total_vulns }}
                </div>
            </div>
            
            <h4>Önemli Bulgular</h4>
            <ul class="findings">
                {% for vuln in ai_analysis.rule_based if vuln.severity in ['CRITICAL','HIGH'] %}
                <li class="{{ vuln.severity|lower }}">
                    <strong>[{{ vuln.severity }}]</strong> {{ vuln.recommendation }}
                    <small>{{ vuln.category }} | {{ vuln.id }}</small>
                </li>
                {% endfor %}
            </ul>
            
            <h4>AI Önerileri</h4>
            <div class="ai-recommendations">
                {% for insight in ai_analysis.ai_insights %}
                <p>🔮 {{ insight }}</p>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <div class="section" id="dns-records">
            <h3 class="section-title">DNS Records</h3>
            <table>
                {% for record_type, records in dns_records.items() %}
                <tr>
                    <th colspan="3">{{ record_type }} Records</th>
                </tr>
                {% for record in records %}
                <tr>
                    <td colspan="3">{{ record }}</td>
                </tr>
                {% endfor %}
                {% endfor %}
            </table>
        </div>

        {% if whois %}
        <div class="section" id="whois">
            <h3 class="section-title">WHOIS Information</h3>
            <table>
                {% for key, value in whois.items() %}
                <tr>
                    <th>{{ key }}</th>
                    <td>{{ value }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
        {% endif %}

        {% if nmap %}
        <div class="section" id="nmap">
            <h3 class="section-title">5. Gelişmiş Nmap Taraması (-sS -A)</h3>
            {% for host, data in nmap.items() %}
            <h4>{{ host }}</h4>
            <table>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
                {% for port, port_data in data.ports.items() %}
                <tr>
                    <td>{{ port }}</td>
                    <td>{{ port_data.state }}</td>
                    <td>{{ port_data.service }}</td>
                    <td>{{ port_data.version }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endfor %}
        </div>
        {% endif %}

        <div class="footer">
            <p>Report generated by SecurityTool | Confidential</p>
        </div>
    </div>
</body>
</html>

        """
    
    async def run_ai_analysis(self):
        if not self.report_data:
            print("[-] Önce tarama yapmalısınız")
            return
    
        print("\n[+] AI güvenlik analizi başlatılıyor...")
        results = self.analyzer.analyze(self.report_data)
        
        print("\n=== 🔍 GÜVENLİK ÖZETİ ===")
        print(f"Toplam {results['summary_stats']['total_vulns']} zafiyet")
        print(f"CRITICAL: {results['summary_stats']['critical']}, HIGH: {results['summary_stats']['high']}")
        
        print("\n=== 🚨 KRİTİK BULGULAR ===")
        for vuln in [v for v in results['rule_based'] if v['severity'] in ['CRITICAL', 'HIGH']]:
            print(f"\n[{vuln['severity']}] {vuln['recommendation']}")
            print(f"Kategori: {vuln['category']} | ID: {vuln['id']}")
        
        print("\n=== 🤖 AI İÇGÖRÜLERİ ===")
        for insight in results['ai_insights']:
            print(f"- {insight}")

        self.report_data['ai_analysis'] = results

    def show_ascii_art(self):
        print(self.ascii_art)
    
    def get_ip_from_domain(self, domain):
        try:
            ip = socket.gethostbyname(domain)
            print(f"[+] {domain} IP adresi: {ip}")
            self.report_data['target']['ip'] = ip
            return ip
        except socket.gaierror:
            print(f"[-] {domain} için IP alınamadı.")
            return None

    def dns_lookup(self, domain):
        self.report_data['dns_records'] = DNSLookup.run(domain)

    def whois_lookup(self, domain):
        self.report_data['whois'] = WhoisLookup.run(domain)

    def advanced_nmap_scan(self, target):
        scanner = NmapScanner()
        self.report_data['nmap'] = scanner.run(target)


                    
    def set_target(self, target):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        parsed = urlparse(target)
        self.target_url = f"{parsed.scheme}://{parsed.netloc}"
        self.target_domain = parsed.hostname
        self.target_ip = self.get_ip_from_domain(self.target_domain)
        
        self.report_data['target'] = {
            'url': self.target_url,
            'domain': self.target_domain,
            'ip': self.target_ip
        }

    def check_ssl_configuration(self):
        if not self.target_domain:
            print("[-] Önce bir hedef belirleyin")
            return

        self.report_data['ssl_tests'] = SSLTester.run(self.target_domain)

    def check_wayback_machine(self):
        if not self.target_domain:
            print("[-] Önce bir hedef belirleyin")
            return

        self.report_data['wayback_data'] = WaybackMachine.run(self.target_domain)

    def generate_html_report(self, filename="security_report.html"):
        ReportGenerator.generate(self.report_data, self.html_template, filename)

    def show_main_menu(self):
        print("\n----- ANA MENÜ -----")
        print("1. Security Research Tools")
        print("2. BadUSB Payload Generator")
        print("3. Exit")
        return input("Seçiminiz: ")

    def show_security_tools_menu(self):
        print("\n----- Güvenlik Test Aracı -----")
        print("1. Hedef Belirle (URL veya Domain)")
        print("2. IP Adresi Bul (Domain'den)")
        print("3. DNS Lookup")
        print("4. Whois Lookup")
        print("5. Gelişmiş Nmap Taraması (-sS -A)")
        print("6. SSL/TLS Testleri")
        print("7. Wayback Machine Taraması")
        print("8. 🔍 AI Güvenlik Analizi")
        print("9. HTML Rapor Oluştur")
        print("10. Çıkış")
        return input("Seçiminiz: ")

    async def run_security_tools(self):
        while True:
            choice = self.show_security_tools_menu()
            
            if choice == '1':
                target = input("Hedef URL veya Domain girin: ")
                self.set_target(target)
                
            elif choice == '2':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.get_ip_from_domain(self.target_domain)
                    
            elif choice == '3':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.dns_lookup(self.target_domain)
                    
            elif choice == '4':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.whois_lookup(self.target_domain)
                    
            elif choice == '5':
                if not self.target_ip:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    target = input(f"Taranacak hedef (varsayılan: {self.target_ip}): ") or self.target_ip
                    self.advanced_nmap_scan(target)
                    
            elif choice == '6':
                        if not self.target_domain:
                            print("[-] Önce bir hedef belirleyin (Menü 1)")
                        else:
                            try:
                                print(f"\n[+] SSL/TLS testleri başlatılıyor (max 30sn): {self.target_domain}")
                               
                               # Thread ile zaman aşımı kontrollü çalıştırma
                                with concurrent.futures.ThreadPoolExecutor() as executor:
                                    future = executor.submit(SSLTester.run, self.target_domain)
                                    results = future.result(timeout=30)  # 30 saniye timeout
                                
                                if results:
                                    print("\n[+] Test Sonuçları:")
                                    for test, data in results.items():
                                        print(f"{test}: {data['value']} ({data['status']})")
                                    self.report_data['ssl_tests'] = results
                                else:
                                    print("[-] Sonuç alınamadı")
                        
                            except concurrent.futures.TimeoutError:
                                print("\n[-] Testler 30 saniyede tamamlanamadı! Ana menüye dönülüyor...")
                            except Exception as e:
                                print(f"[-] Hata: {str(e)}")
                            finally:
                                input("\nDevam etmek için Enter'a basın...")
                    
            elif choice == '7':
                if not self.target_domain:
                    print("[-] Önce bir hedef belirleyin (Menü 1)")
                else:
                    self.check_wayback_machine()
                    
            elif choice == '8':
                await self.run_ai_analysis()
                
            elif choice == '9':
                filename = input("Rapor dosya adı: ") or "security_report.html"
                self.generate_html_report(filename)
                
            elif choice == '10':
                print("[+] Çıkış yapılıyor...")
                break
                
            else:
                print("[-] Geçersiz seçim!")

    def run_badusb_tool(self):
        BadUSBGenerator.run()
    
    async def run(self):
        self.show_ascii_art()
        
        while True:
            choice = self.show_main_menu()
            
            if choice == '1':
                await self.run_security_tools()
                
            elif choice == '2':
                self.run_badusb_tool()
                
            elif choice == '3':
                print("[+] Çıkış yapılıyor...")
                break
                
            else:
                print("[-] Geçersiz seçim!")