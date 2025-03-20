# IPshark

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/alexsilva-sh/IPshark)](https://github.com/alexsilva-sh/IPshark/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alexsilva-sh/IPshark)](https://github.com/alexsilva-sh/IPshark/pulls)

#### Análise de Reputação de IPs

IPshark é uma ferramenta Python simples e intuitiva para analisar a reputação de endereços IP usando APIs de serviços como AbuseIPDB, VirusTotal e IPinfo. Ele permite que você obtenha informações sobre a reputação de um IP, sua localização e outros detalhes relevantes diretamente do seu terminal.

## Demonstração

IPshark está em desenvolvimento ativo. Sinta-se à vontade para contribuir com melhorias, correções de bugs e novas funcionalidades.

**Atenção:** As APIs utilizadas em IPshark têm limites de requisição. Consulte a documentação de cada serviço para mais informações.

## Como usar

1.  Clone o repositório:

    ```bash
    git clone [https://github.com/alexsilva-sh/IPshark.git](https://www.google.com/search?q=https://github.com/alexsilva-sh/IPshark.git)
    cd IPshark
    ```

2.  Instale as dependências:

    ```bash
    pip install requests pyperclip ipaddress
    ```

3.  Substitua as chaves de API no código (`ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` e `IPINFO_API_KEY`) pelas suas próprias chaves.

4.  Execute o script:

    ```bash
    python ipshark.py
    ```

5.  Digite os IPs que deseja consultar, separados por vírgula, ou 'sair' para encerrar.

## Funcionalidades

* Validação de endereços IP.
* Consulta de reputação em AbuseIPDB e VirusTotal.
* Obtenção de informações de localização via IPinfo.
* Formatação de saída com detalhes de reputação e localização.
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
