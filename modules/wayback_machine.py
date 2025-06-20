import requests

class WaybackMachine:
    @staticmethod
    def run(domain):
        try:
            print(f"\n[+] Wayback Machine'den tarihsel veriler aranıyor: {domain}")
            print("[*] Wayback Machine API'sine sorgu gönderiliyor...")
            
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
            response = requests.get(wayback_url, timeout=10)
            data = response.json()
            
            records = []
            for row in data[1:]:
                records.append({
                    'timestamp': row[1],
                    'url': f"https://web.archive.org/web/{row[1]}/{row[2]}",
                    'status_code': row[4]
                })
            
            print(f"\n[+] Bulunan kayıt sayısı: {len(records)}")
            for record in records[:10]:
                print(f"{record['timestamp']} - {record['url']} ({record['status_code']})")
            
            return records[:100]  # İlk 100 kaydı döndür
            
        except Exception as e:
            print(f"[-] Wayback Machine hatası: {e}")
            return []