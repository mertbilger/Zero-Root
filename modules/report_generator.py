from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template
from io import BytesIO
import base64
import os

class ReportGenerator:
    @staticmethod
    def generate(report_data, html_template, filename="security_report.html"):
        print(f"\n[+] HTML rapor oluşturuluyor: {filename}")
        print("[*] Veriler derleniyor...")
        
        try:
            cert_chart = ReportGenerator.generate_certificate_chart()
            
            report_context = {
                'target': report_data['target'].get('domain'),
                'target_url': report_data['target'].get('url'),
                'target_ip': report_data['target'].get('ip'),
                'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'ssl_tests': report_data.get('ssl_tests', {}),
                'wayback_data': report_data.get('wayback_data', []),
                'dns_records': report_data.get('dns_records', {}),
                'whois': report_data.get('whois', {}),
                'nmap': report_data.get('nmap', {}),
                'cert_chart': cert_chart,
                'ai_analysis': report_data.get('ai_analysis', {})
            }
            
            template = Template(html_template)
            html_content = template.render(report_context)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[+] Rapor başarıyla oluşturuldu: {os.path.abspath(filename)}")
            
        except Exception as e:
            print(f"[-] Rapor oluşturma hatası: {e}")

    @staticmethod
    def generate_certificate_chart():
        try:
            dates = pd.date_range(start='2023-01-01', end='2024-12-31', freq='M')
            values = [i**2 for i in range(len(dates))]
            
            plt.figure(figsize=(10, 3))
            plt.plot(dates, values)
            plt.title('Certificate Validity Timeline')
            plt.grid(True)
            
            buffer = BytesIO()
            plt.savefig(buffer, format='png')
            buffer.seek(0)
            chart_base64 = base64.b64encode(buffer.read()).decode('utf-8')
            plt.close()
            
            return chart_base64
            
        except Exception as e:
            print(f"[-] Grafik oluşturma hatası: {e}")
            return ""