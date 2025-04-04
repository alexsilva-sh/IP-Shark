import requests
import pyperclip
import ipaddress
import csv
import os
import tkinter as tk
from tkinter import filedialog
import unicodedata
from datetime import datetime, timedelta

# Substitua 'api' pelas suas chaves de API
ABUSEIPDB_API_KEY = 'api'
VIRUSTOTAL_API_KEY = 'api'

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_ip_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def check_ip_virustotal(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def get_location(ip):
    try:
        url = f'http://ip-api.com/json/{ip}?fields=status,country,countryCode,city'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if data.get('status') == 'fail':
            return 'N/A', 'N/A'

        city = data.get('city', 'N/A')
        country_code = data.get('countryCode', 'N/A')
        country_name = translate_country_name(country_code)
        return city, country_name
    except requests.exceptions.RequestException:
        return 'N/A', 'N/A'

def get_domain_from_abuseipdb(abuseipdb_result):
    try:
        return remover_acentos(abuseipdb_result['data'].get('domain', 'N/A')) if abuseipdb_result else 'N/A'
    except KeyError:
        return 'N/A'

def remover_acentos(texto):
    """ Remove acentos e caracteres especiais de um texto """
    if isinstance(texto, str):
        return ''.join(c for c in unicodedata.normalize('NFD', texto) if unicodedata.category(c) != 'Mn')
    return texto

def is_whitelisted_abuseipdb(abuseipdb_result):
    try:
        return "Sim" if abuseipdb_result['data'].get('isWhitelisted', False) else "Não"
    except KeyError:
        return "Não"

def translate_country_name(country_code):
    try:
        url = f'https://restcountries.com/v3.1/alpha/{country_code}'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data[0]['translations']['por']['common'] if 'translations' in data[0] else data[0]['name']['common']
    except requests.exceptions.RequestException:
        return country_code

def escolher_diretorio():
    """ Abre uma janela para o usuário escolher o diretório de salvamento """
    root = tk.Tk()
    root.withdraw()
    diretorio = filedialog.askdirectory(title="Escolha onde salvar o arquivo CSV")
    return diretorio if diretorio else os.getcwd()  # Se não escolher, salva no diretório atual

def save_to_csv(results):
    """ Salva os resultados em um arquivo CSV no diretório escolhido """
    diretorio = escolher_diretorio()
    filename = os.path.join(diretorio, "consulta_ips.csv")

    headers = ["IP", "Score AbuseIPDB", "Score VirusTotal", "Dominio", "Pais", "Cidade", "Ultima Denuncia", "AbuseIPDB Link", "VirusTotal Link"]

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)  # Escreve o cabeçalho
        writer.writerows(results)  # Escreve os dados
    print(" ")
    print(f"***** Resultados salvos em: {filename} *****")
    print(" ")

def format_output(ip, abuseipdb_result, virustotal_result, city, country, domain, index):
    try:
        abuse_confidence = abuseipdb_result['data']['abuseConfidenceScore'] if abuseipdb_result else 0
        vt_score = virustotal_result['data']['attributes']['last_analysis_stats']['malicious'] if virustotal_result else 0
        #reputation_status = "Malicioso" if abuse_confidence > 0 or vt_score > 0 else "NÃO malicioso"

        abuseipdb_link = f"https://www.abuseipdb.com/check/{ip}"
        virustotal_link = f"https://www.virustotal.com/gui/ip-address/{ip}"

        last_reported_at = abuseipdb_result['data'].get('lastReportedAt') if abuseipdb_result else None
        if last_reported_at:
            utc_time = datetime.fromisoformat(last_reported_at.replace('Z', '+00:00'))
            brasilia_time = utc_time - timedelta(hours=3)
            last_reported_at_formatted = brasilia_time.strftime('%d/%m/%Y %H:%M:%S')
        else:
            last_reported_at_formatted = 'Nao possui denuncias'

        return [
            ip,
            f"{abuse_confidence}%",
            f"{vt_score}",
            domain,
            country,
            city,
            last_reported_at_formatted,
            abuseipdb_link,
            virustotal_link
        ]
    except Exception as e:
        return [f"Erro ao formatar a saída para {ip}: {e}", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]

def format_terminal_output(ip, abuseipdb_result, virustotal_result, city, country, domain, index):
    try:
        abuse_confidence = abuseipdb_result['data']['abuseConfidenceScore'] if abuseipdb_result else 0
        vt_score = virustotal_result['data']['attributes']['last_analysis_stats']['malicious'] if virustotal_result else 0
        whitelisted = is_whitelisted_abuseipdb(abuseipdb_result)

        abuseipdb_link = f"https://www.abuseipdb.com/check/{ip}"
        virustotal_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
        reputation_status = "Possui má reputação" if abuse_confidence > 0 or vt_score > 0 else "NÃO possui má reputação"

        last_reported_at = abuseipdb_result['data'].get('lastReportedAt') if abuseipdb_result else None
        if last_reported_at:
            utc_time = datetime.fromisoformat(last_reported_at.replace('Z', '+00:00'))
            brasilia_time = utc_time - timedelta(hours=3)
            last_reported_at_formatted = brasilia_time.strftime('%d/%m/%Y %H:%M:%S')
        else:
            last_reported_at_formatted = 'Não possui denúncias'

        output = f"""
[{index}] {ip} - {reputation_status}
IP em Whitelist no AbuseIPDB: {whitelisted}
Score no AbuseIPDB: {abuse_confidence}%
Score no VirusTotal: {vt_score}
Nome de domínio: {domain}
País e cidade: {country}, {city}
Último relatório no AbuseIPDB: {last_reported_at_formatted}
- {abuseipdb_link}
- {virustotal_link}"""
        return output
    except Exception as e:
        return f"Erro ao formatar a saída para {ip}: {e}"

def main():
    print("""                                                                 
              ########                              
              ############                          
              ##############                        
              ################                                  
  _____ _____     _____ _                _    
 |_   _|  __  |  / ____| |              | |   
   | | | |__) | | (___ | |__   __ _ _ __| | __
   | | |  ___/   |___ || '_ | | _` | '__| |/ /
  _| |_| |       ____) | | | | (_| | |  |   /
 |_____|_|      |_____/|_| |_||__,_|_|  |_||_|
              #######################                
              ############################                       
              ################################          
              #####################################          
              ##########################################      
              ################################################
              # Desenvolvido por @alexsilva-sh #####################
              # Contribua https://github.com/alexsilva-sh/IP-Shark #####
    """)

    while True:
        ips_input = input("Digite os IPs para consulta (separados por vírgula) ou 'sair' para encerrar: ")
        if ips_input.lower() == 'sair':
            break

        ips = [ip.strip() for ip in ips_input.split(',')]
        all_outputs = ""
        all_results = []

        for index, ip in enumerate(ips, 1):
            if not is_valid_ip(ip):
                print(f"IP inválido: {ip}.")
                continue

            abuseipdb_result = check_ip_abuseipdb(ip)
            virustotal_result = check_ip_virustotal(ip)
            city, country = get_location(ip)
            domain = get_domain_from_abuseipdb(abuseipdb_result)

            csv_result = format_output(ip, abuseipdb_result, virustotal_result, city, country, domain, index)
            all_results.append(csv_result)

            terminal_output = format_terminal_output(ip, abuseipdb_result, virustotal_result, city, country, domain, index)
            all_outputs += terminal_output + "\n"

        if len(ips) >= 5:
            save_to_csv(all_results)
        else:
            print(all_outputs)
            pyperclip.copy(all_outputs)
            print("O resultado foi copiado para a área de transferência.")
            print("#######################################################################################################")
            print("#######################################################################################################")
            print(" ")
            print(" ")

if __name__ == "__main__":
    main()
