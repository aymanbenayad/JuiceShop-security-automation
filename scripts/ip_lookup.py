import requests


ips_file = open("logs/ips.txt", 'r')
ips = ips_file.read()
ipslist = ips.strip().split(',')

for ip in ipslist:
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json")
        res.raise_for_status()  # Vérifie si la requête a échoué
        print(f"\nIP {ip} Info: {res.json()}")
    except requests.RequestException as e:
        print(f"\nErreur lors de la récupération des infos pour l'IP {ip}: {e}")

ips_file.close()