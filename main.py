import requests
import os
import sys
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")


def target_check(target):
    if not API_KEY:
        print("Erro: API key não encontrada (.env)")
        return None

    headers = {"x-apikey": API_KEY}

    # CLEAR INPUT
    target = target.replace("https://", "").replace("http://", "").strip("/")

    if target.replace(".", "").isdigit():
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{target}"

    try:
        response = requests.get(url, headers=headers)
    except Exception as e:
        print("Erro de conexão:", e)
        return None

    if response.status_code == 401:
        print("Erro: API key inválida ou não autorizada (401)")
        return None

    if response.status_code == 404:
        print("Erro: alvo não encontrado (404)")
        return None

    if response.status_code != 200:
        print("Erro na requisição:", response.status_code)
        print(response.text)
        return None

    return response.json()


def analysis(data):
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except KeyError:
        print("Erro ao interpretar dados da API")
        return None

    malicious = stats.get("malicious", 0)
    suspect = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    score = malicious + suspect

    if score == 0:
        rep = "HARMLESS"
    elif score < 5:
        rep = "SUSPECT"
    else:
        rep = "MALICIOUS"

    return {
        "malicious": malicious,
        "suspect": suspect,
        "harmless": harmless,
        "rep": rep
    }


def report(target, result):
    relatorio = f"""
Target: {target}

Results:
- Malicious: {result['malicious']}
- Suspicious: {result['suspect']}
- Harmless: {result['harmless']}

Result: {result['rep']}
"""

    print(relatorio)


def main():
   
   #CLI ARGUMENT FOR DOCKER
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Insert an IP or URL: ")

    data = target_check(target)

    if not data:
        return

    result = analysis(data)

    if not result:
        return

    report(target, result)


if __name__ == "__main__":
    main()