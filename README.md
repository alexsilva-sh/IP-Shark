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

1.  Clone o repositório:

    ```bash
    git clone [https://github.com/alexsilva-sh/IPshark.git](https://github.com/alexsilva-sh/IPshark.git)
    cd IPshark
    ```

2.  Instale as dependências:

    ```bash
    pip install requests pyperclip ipaddress
    ```

3.  Substitua as chaves de API no código (`ABUSEIPDB_API_KEY` e `VIRUSTOTAL_API_KEY`) pelas suas próprias chaves.

4.  Execute o script:

    ```bash
    python ipshark.py
    ```

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
