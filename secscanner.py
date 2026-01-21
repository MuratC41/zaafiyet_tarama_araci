import csv
import re
import subprocess

def renkli_yaz(metin, renk):
    kodlar = {
        "kirmizi": "\033[91m",
        "sari": "\033[93m",
        "yesil": "\033[92m",
        "reset": "\033[0m"
    }
    return f"{kodlar[renk]}{metin}{kodlar['reset']}"

def run_nmap_scan(hedef):
    hedef = hedef.strip().split("://")[-1]
    print(f"[*] {hedef} adresi taranıyor...\n")

    try:
        sonuc = subprocess.run(
            ["nmap", "-sV", hedef],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if sonuc.returncode != 0:
            print("[!] Nmap hatası:", sonuc.stderr)
            return None

        print("[+] Tarama tamamlandı:\n")
        print(sonuc.stdout)
        return sonuc.stdout

    except Exception as e:
        print(f"[!] Nmap çalıştırılırken hata oluştu: {e}")
        return None

def read_cve_file(dosya_adi):
    cve_listesi = []
    try:
        with open(dosya_adi, mode='r', encoding='utf-8') as dosya:
            okuyucu = csv.DictReader(dosya)
            for satir in okuyucu:
                try:
                    puan = float(satir.get("cvss", "0").strip() or 0)
                except:
                    puan = 0.0

                veri = {
                    "id": satir.get("id", ""),
                    "cwe_name": satir.get("cwe_name", ""),
                    "summary": satir.get("summary", ""),
                    "cvss": puan,
                    "access_authentication": satir.get("access_authentication", ""),
                    "access_complexity": satir.get("access_complexity", ""),
                    "access_vector": satir.get("access_vector", ""),
                    "impact_availability": satir.get("impact_availability", ""),
                    "impact_confidentiality": satir.get("impact_confidentiality", ""),
                    "impact_integrity": satir.get("impact_integrity", "")
                }
                cve_listesi.append(veri)
        return cve_listesi
    except Exception as e:
        print(f"[!] CVE dosyası okunamadı: {e}")
        return []

def parse_services_from_nmap(cikti):
    servisler = []
    for satir in cikti.splitlines():
        if re.match(r"^\d+/[tcpudp]+", satir):
            parcalar = satir.split()
            if len(parcalar) >= 3:
                port = parcalar[0].split("/")[0]
                servis = parcalar[2].lower()
                versiyon = " ".join(parcalar[3:]).lower() if len(parcalar) > 3 else ""
                servisler.append((port, servis, versiyon))
    return servisler

def match_cve_strict(servisler, cve_verisi):
    eslesenler = []
    for port, servis, versiyon in servisler:
        for cve in cve_verisi:
            icerik = f"{cve['summary']} {cve['cwe_name']}".lower()
            if (port and str(port) in icerik) and (servis and servis in icerik) and (versiyon and versiyon.split()[0] in icerik):
                eslesenler.append(cve)
    eslesenler.sort(key=lambda x: x["cvss"], reverse=True)
    return eslesenler

def print_cve_info(cve_liste):
    for cve in cve_liste:
        puan = cve["cvss"]
        renk = "kirmizi" if puan >= 7 else "sari" if puan >= 4 else "yesil"

        print(renkli_yaz(f"\n- CVE: {cve['id']} (CVSS: {puan})", renk))
        if cve["cwe_name"]:
            print(f"  - CWE: {cve['cwe_name']}")
        if cve["summary"]:
            print(f"  - Özeti: {cve['summary']}")
        if cve["access_authentication"]:
            print(f"  - Authentication: {cve['access_authentication']}")
        if cve["access_complexity"]:
            print(f"  - Complexity: {cve['access_complexity']}")
        if cve["access_vector"]:
            print(f"  - Vector: {cve['access_vector']}")
        if cve["impact_availability"]:
            print(f"  - Etki (Availability): {cve['impact_availability']}")
        if cve["impact_confidentiality"]:
            print(f"  - Etki (Confidentiality): {cve['impact_confidentiality']}")
        if cve["impact_integrity"]:
            print(f"  - Etki (Integrity): {cve['impact_integrity']}")
        print("-" * 50)

def run_pipeline():
    hedef = input("Hedef domaini girin: ").strip()
    if not hedef:
        print("[!] Geçerli bir domain girilmedi.")
        return

    tarama = run_nmap_scan(hedef)
    if not tarama:
        return

    servisler = parse_services_from_nmap(tarama)
    cve_verisi = read_cve_file("cve.csv")
    eslesen_cve = match_cve_strict(servisler, cve_verisi)

    if not eslesen_cve:
        print("\n[!] Uygun CVE bulunamadı.")
    else:
        print("\n[+] Eşleşen güvenlik açıkları:")
        print_cve_info(eslesen_cve)

if __name__ == "__main__":
    run_pipeline()
