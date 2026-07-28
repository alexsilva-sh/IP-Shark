# 🦈 IP Shark
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/alexsilva-sh/IP-Shark)](https://github.com/alexsilva-sh/IP-Shark/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alexsilva-sh/IP-Shark)](https://github.com/alexsilva-sh/IP-Shark/pulls)

Ferramenta Python com interface gráfica para análise de reputação de IPs, hashes e domínios, integrando múltiplas fontes de inteligência de ameaças.

O IP Shark combina consultas em AbuseIPDB, VirusTotal, IBM X-Force, AlienVault, IPinfo e JoeSandbox, com execução paralela, exportação de resultados em Excel e geração de recomendações automáticas.

---

## 🔍 Funcionalidades Principais

### ✅ Análise de IPs
- **AbuseIPDB**: Score de abuso, data da última denúncia e detecção de whitelist.
- **VirusTotal**: Verificação em múltiplos motores antivírus.
- **IBM X-Force**: Score de risco (consulta automatizada via Selenium).
- **IPinfo**: Localização do IP (cidade e país) com tradução automática do nome do país.
- Execução paralela com até 10 IPs simultâneos e exibição ordenada dos resultados.
- Exportação em **Excel (.xlsx)** com formatação profissional e links diretos para todas as plataformas.
- Pré-análise automática que recomenda bloqueio ou reporte ao MSS.

### 🧪 Análise de Hashes (MD5, SHA1, SHA256)
- **VirusTotal**: Score, nome do arquivo e data da última análise.
- **IBM X-Force**: Nível de risco do hash.
- **AlienVault**: Quantidade de pulsos de ameaça relacionados.
- **JoeSandbox**: Detecção de relatórios de sandbox disponíveis.
- Exportação em **Excel (.xlsx)** com todos os links.
- Pré-análise com recomendações automáticas.

### 🌐 Análise de Domínios
- **VirusTotal**: Score de reputação do domínio.
- **IBM X-Force**: Score do domínio (via Selenium).
- **AlienVault**: Quantidade de pulsos relacionados ao domínio.
- Resolução automática de IPs associados via DNS público do Google (`dns.google/resolve`) e `socket.gethostbyname_ex()`, com análise completa de cada IP resolvido.
- Exportação em **Excel (.xlsx)** com abas separadas: uma para domínios e uma por domínio contendo os IPs associados.
- Pré-análise automática com recomendações de bloqueio ou inspeção.

---

## ⚙️ Recursos Adicionais
- Interface moderna com **modo escuro total** e toggle switches animados.
- **Suporte a dois idiomas**: Português 🇧🇷 e Inglês 🇺🇸, alternável em tempo real.
- Execução paralela com status dinâmico das consultas em andamento.
- Abas dedicadas para **IP**, **Hash** e **Domínio**.
- Gerenciamento automático do ChromeDriver com pool de drivers e fechamento completo dos processos ao encerrar.
- Verificação automática de nova versão no GitHub ao iniciar.
- Tela própria para cadastrar as chaves de API, que ficam **criptografadas** na máquina do usuário.
- Entrada flexível: aceita vírgulas, espaços ou quebras de linha.
- Resultados coloridos: 🔴 vermelho para reputação ruim, 🟡 âmbar para casos que exigem validação, 🟢 verde para limpo.

---

## 🔐 Configuração de APIs

Abra o IP Shark e clique em **🗝 Configurar API**. Preencha as chaves dos serviços que você
quiser usar e clique em **Salvar**.

As chaves ficam gravadas só na sua máquina, em `%LOCALAPPDATA%\IPShark\api_keys.dat`,
criptografadas pela DPAPI do Windows com as credenciais da sua conta. Na prática, isso
significa que apenas o seu usuário, naquele computador, consegue lê-las. As chaves não são
enviadas para nenhum lugar além das próprias APIs consultadas.

Se você vem de uma versão anterior à v3.1 e usava o `config/api.env`, suas chaves são
importadas automaticamente na primeira execução. A tela de configuração também oferece apagar
o arquivo antigo, que guardava tudo em texto puro e não é mais lido pelo programa.

Obtenha suas chaves gratuitas nos links abaixo:
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [AbuseIPDB](https://www.abuseipdb.com/account/api)
- [IPinfo](https://ipinfo.io/signup)
- [AlienVault](https://otx.alienvault.com/api)

---

## 🚀 Como usar

1. Execute `ipshark.exe`.
2. Selecione o idioma desejado: 🇧🇷 PT ou 🇺🇸 EN.
3. Escolha a aba **IP**, **Hash** ou **Domínio**.
4. Cole os valores a serem consultados (separados por vírgula, espaço ou quebra de linha).
5. Configure as opções com os toggles disponíveis:
   - **IBM X-Force**: ativa/desativa a consulta ao IBM X-Force.
   - **Pré-análise**: gera recomendação automática ao final da varredura.
   - **Cliente tem MSS?**: ajusta o texto da recomendação para incluir reporte ao MSS.
   - **Verificar IPs associados** *(somente aba Domínio)*: resolve e analisa os IPs de cada domínio.
6. Clique em **🔍 Consultar** para iniciar.
7. Os resultados aparecem na área de saída colorida e podem ser:
   - **Copiados** para a área de transferência;
   - **Exportados** para Excel (.xlsx) com formatação profissional;
   - **Cancelados** a qualquer momento com o botão ❌ Cancelar.

---

## 🛠 Desenvolvimento

Ambos os scripts criam e reutilizam uma venv em `.venv/` automaticamente — não é preciso
preparar nada antes.

```bat
build.bat            :: gera dist\ipshark.exe (venv + dependências + PyInstaller)
build.bat fast run   :: reaproveita o cache e abre o executável ao final
run_tests.bat        :: roda as suítes de tests\
```

`build.bat help` lista as demais opções (`publish`, `clean`).

Os testes não usam rede, Selenium nem Chrome: as respostas de API são simuladas e o pool de
navegadores roda com dublês. Rode-os antes de gerar um executável para distribuir.

---

**Demonstração**

![Demonstração de uso](assets/imagem.png)
