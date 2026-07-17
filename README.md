# Packet Sniffer - Guia de Execução

Este projeto é um analisador de rede desenvolvido em **Python** com a biblioteca **Scapy**, capaz de capturar e analisar tráfego em tempo real.

---

## 1. Dependências (Bibliotecas)

Para o funcionamento correto do sniffer, é necessário instalar a biblioteca **Scapy**:

```bash
pip install scapy
```

---

## 2. Como Selecionar a Interface

Antes de iniciar, deves listar as interfaces de rede do teu sistema para saber qual usar (ex: `eth0`, `wlan0`, `wlp62s0`):

```bash
ip a
```

### Sintaxe Completa
 
```bash
sudo python3 main.py -i <nome_da_interface> -m <modo> -o <ficheiro> -v <verbosidade>
```


### Argumentos Disponíveis
 
| Argumento | Abreviatura | Valores | Padrão | Descrição |
|---|---|---|---|---|
| `--interface` | `-i` | nome da interface | *(obrigatório)* | Interface de rede a capturar (ex: `eth0`, `wlan0`) |
| `--mode` | `-m` | `live`, `log`, `both` | `live` | Modo de captura: só consola, só ficheiro, ou ambos |
| `--output` | `-o` | caminho do ficheiro | `None` | Ficheiro de saída para guardar os pacotes (ex: `captura.txt`) |
| `--verbosity` | `-v` | `verbose`, `compact` | `verbose` | Nível de detalhe na consola |
 
### Exemplos de Uso
 
```bash
# Captura básica na consola
sudo python3 main.py -i eth0
 
# Guardar captura num ficheiro
sudo python3 main.py -i eth0 -m log -o captura.txt
 
# Captura na consola e em ficheiro simultaneamente, modo compacto
sudo python3 main.py -i wlan0 -m both -o captura.txt -v compact
```
 
---

## 3. Filtros e Funcionalidades

### Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| **Captura Live** | Visualização imediata dos pacotes na consola |
| **Log em Ficheiro** | Gravação para análise posterior usando `-o ficheiro.txt` |
| **Identificação Automática** | Deteta protocolos como ARP, ICMP, TCP, IPv4, DHCP e WiFi |
| **Análise de Fragmentação** | Deteta automaticamente pacotes IPv4 fragmentados |

### Ativar Filtros (Modo de Análise)

Após terminar a captura com `Ctrl+C`, o programa entra no **Modo de Análise Interativo**. Podes digitar:

| Comando | Descrição |
|---|---|
| `tcp`, `dhcp`, `icmp`, `ipv4`, `wifi`, `arp` | Lista pacotes de um protocolo específico |
| `status <protocolo>` | Ver estatísticas detalhadas dos protocolos icmp,arp,tcp e wifi (ex: `status tcp`) |
| `fragments ipv4` | Ver pacotes IPv4 fragmentados de forma detalhada |
| `filter ip <IP>` | Isolar tráfego de um endereço IP específico |
| `filter proto <NOME>` | Filtrar por protocolo à escolha (ex: `filter proto ARP`) |
| `filter mac <MAC>` | Filtrar por um endereço físico específico |

---

## 4. Como Correr (CORE vs PC Local)

### No Ambiente CORE

1. Abre o terminal de um nó da topologia (ex: um Router ou Host).
2. Executa o comando:

```bash
sudo python3 main.py -i eth0
```

3. Gere tráfego noutro nó com comandos como `ping <ip_destino>` ou `nc`.

### No PC Local

1. Abre o terminal na pasta do projeto.
2. Executa o comando:

```bash
sudo python3 main.py -i <tua_interface_ativa> -m live -v compact
```

3. Gere tráfego real navegando na internet ou fazendo pings no terminal.
