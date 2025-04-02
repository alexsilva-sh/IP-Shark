# IPshark

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/alexsilva-sh/IP-Shark)](https://github.com/alexsilva-sh/IP-Shark/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alexsilva-sh/IP-Shark)](https://github.com/alexsilva-sh/IP-Shark/pulls)

#### Análise de Reputação de IPs

IPshark é uma ferramenta Python simples e intuitiva para analisar a reputação de endereços IP usando APIs de serviços como AbuseIPDB e VirusTotal. Ele permite que você obtenha informações sobre a reputação de um IP diretamente do seu terminal.

## Obtenha as chaves API dos serviços mencionados:
- API do VirusTotal: https://www.virustotal.com/gui/home/upload
- API do AbuseIPDB: https://www.abuseipdb.com/account/api

## Demonstração

IPshark está em desenvolvimento ativo. Sinta-se à vontade para contribuir com melhorias, correções de bugs e novas funcionalidades.

**Atenção:** As APIs utilizadas em IPshark têm limites de requisição. Consulte a documentação de cada serviço para mais informações.

## Como usar

1.  Instalar o python:

    - Instale a partir do programa do windows "Microsoft Store", para simplificar o processo de integração do python no cmd.

2.  Instale as dependências.

    - Abra o CMD e faça o comando abaixo:
    ```bash
    pip install requests pyperclip ipaddress
    ```

3.  Substitua as chaves de API no código (`api`) pelas suas próprias chaves.

4.  Execute o script:

    ```bash
    python ipshark.py
    ```
    - Ou abra o arquivo ipshark.py diretamente no explorador de arquivos, ou pesquisando "ipshark.py" no menu iniciar do windows.

5.  Digite os IPs que deseja consultar, separados por vírgula, ou 'sair' para encerrar.

## Funcionalidades

* Validação de endereços IP.
* Consulta de reputação em AbuseIPDB e VirusTotal.
* Formatação de saída com detalhes de reputação.
* Cópia dos resultados para a área de transferência.

## Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests.

## Licença

IPshark é distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para mais detalhes.

## Autor

Desenvolvido por [alexsilva-sh](https://github.com/alexsilva-sh).

## Dependências

* `requests`
* `pyperclip`
* `ipaddress`
