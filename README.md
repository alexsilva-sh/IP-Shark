# 🦈 IP Shark v2.4.5

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/alexsilva-sh/IP-Shark)](https://github.com/alexsilva-sh/IP-Shark/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alexsilva-sh/IP-Shark)](https://github.com/alexsilva-sh/IP-Shark/pulls)

Ferramenta Python com interface gráfica que permite analisar a reputação de **IPs**, **hashes de arquivos** e **URLs** utilizando diversas fontes confiáveis de inteligência de ameaças. A interface é intuitiva, suporta execução paralela e exportação em CSV, além de oferecer opções de pré-análises automáticas.

---

## 🔍 Funcionalidades Principais

### ✅ Análise de IPs
- **AbuseIPDB**: Score de abuso e verificação de whitelist.
- **VirusTotal**: Detecção por múltiplos antivírus.
- **IBM X-Force**: Score de risco (via Selenium).
- **IPinfo**: Localização do IP (cidade, país).
- **Tradução de Países**: Via APIcountries para português.
- **Formatação de data da última denúncia** no fuso de Brasília.
- **Exportação CSV** com todos os dados e links.

### 🧪 Análise de Hashes (MD5, SHA1, SHA256)
- **VirusTotal**: Score, nome do arquivo, data da última análise.
- **IBM X-Force**: Nível de risco.
- **AlienVault**: Quantidade de pulsos relacionados.
- **JoeSandbox**: Detecção de relatórios disponíveis.
- **Exportação CSV** com todos os links.
- **Pré-análise com recomendações automáticas**.

### 🌐 Análise de URLs
- **VirusTotal**: Score de reputação.
- **IBM X-Force**: Score da URL (via Selenium).
- **AlienVault**: Quantidade de pulsos relacionados à URL.
- **Exportação CSV** com links.

---

## 📁 Funcionalidades Adicionais

- Interface gráfica moderna com **modo escuro**.
- **Execução paralela** com status dinâmico das consultas.
- **Abas separadas** para IP, Hash e URL.
- **Botão para interromper consultas** a qualquer momento.
- **Atualização automática**: Verifica nova versão no GitHub.
- **Validação automática** de IPs e hashes.
- **Compatível com entrada por vírgula, espaço ou quebra de linha.**

---

## 🔐 Configuração de APIs

Crie um arquivo chamado `.env` no mesmo diretório do executável com o seguinte conteúdo:

``env
ABUSEIPDB_API_KEY=xxxxx
VIRUSTOTAL_API_KEY=xxxxx
IPINFO_API_KEY=xxxxx
ALIENVAULT_API_KEY=xxxxx``

Você pode obter suas chaves nos links abaixo:

- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [AbuseIPDB](https://www.abuseipdb.com/account/api)
- [IPinfo](https://ipinfo.io/signup)
- [AlienVault](https://otx.alienvault.com/api)

**Execute o ipshark.exe:**
  - Digite os IPs na caixa de texto, separados por vírgula.
    - Marque a opção "Consultar com IBM X-Force" se desejar incluir essa análise.
    - Clique em "🔍 Realizar consulta".
    - Os resultados serão exibidos na área de saída.
    - Utilize os botões para copiar os resultados ou exportá-los para um arquivo CSV.
   
**Demonstração**

![Demonstração de uso](imagem.png)
