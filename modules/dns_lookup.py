import dns.resolver

class DNSLookup:
    @staticmethod
    def run(domain):
        try:
            print(f"\n[+] {domain} DNS kayıtları:")
            resolver = dns.resolver.Resolver()
            results = {'A': [], 'MX': [], 'NS': [], 'TXT': []}
            
            try:
                a_records = resolver.resolve(domain, 'A')
                print("\nA Kayıtları:")
                results['A'] = [record.address for record in a_records]
                for record in a_records:
                    print(f"IP: {record.address}")
            except dns.resolver.NoAnswer:
                print("A kaydı bulunamadı")
            
            try:
                mx_records = resolver.resolve(domain, 'MX')
                print("\nMX Kayıtları:")
                results['MX'] = [f"{record.exchange} (Priority: {record.preference})" for record in mx_records]
                for record in mx_records:
                    print(f"MX: {record.exchange} (Priority: {record.preference})")
            except dns.resolver.NoAnswer:
                print("MX kaydı bulunamadı")
            
            try:
                ns_records = resolver.resolve(domain, 'NS')
                print("\nNS Kayıtları:")
                results['NS'] = [str(record.target) for record in ns_records]
                for record in ns_records:
                    print(f"Nameserver: {record.target}")
            except dns.resolver.NoAnswer:
                print("NS kaydı bulunamadı")
                
            try:
                txt_records = resolver.resolve(domain, 'TXT')
                print("\nTXT Kayıtları:")
                results['TXT'] = [' '.join([s.decode('utf-8') for s in record.strings]) for record in txt_records]
                for record in txt_records:
                    print(f"TXT: {' '.join([s.decode('utf-8') for s in record.strings])}")
            except dns.resolver.NoAnswer:
                print("TXT kaydı bulunamadı")
                
            return results
            
        except Exception as e:
            print(f"[-] DNS lookup hatası: {e}")
            return {}