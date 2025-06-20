import whois

class WhoisLookup:
    @staticmethod
    def run(domain):
        try:
            print(f"\n[+] {domain} Whois Bilgileri:")
            w = whois.whois(domain)
            
            print(f"\nDomain: {w.domain_name}")
            print(f"Registrar: {w.registrar}")
            print(f"Creation Date: {w.creation_date}")
            print(f"Expiration Date: {w.expiration_date}")
            print(f"Name Servers: {w.name_servers}")
            print(f"Status: {w.status}")
            print(f"Emails: {w.emails}")
            
            return {
                'Domain Name': w.domain_name,
                'Registrar': w.registrar,
                'Creation Date': str(w.creation_date),
                'Expiration Date': str(w.expiration_date),
                'Name Servers': ', '.join(w.name_servers) if w.name_servers else 'N/A',
                'Status': w.status if isinstance(w.status, str) else ', '.join(w.status),
                'Emails': w.emails if isinstance(w.emails, str) else ', '.join(w.emails) if w.emails else 'N/A'
            }
            
        except Exception as e:
            print(f"[-] Whois sorgusu hatası: {e}")
            return {}