"""
Script auxiliar do Exercício 9 — gera tráfego "normal" e "hostil" contra
a API rodando em exercicio9_rate_limit_anomalia.py, dispara a análise e
mostra o resultado do bloqueio.

Pré-requisito: pip install requests
Como usar:
    1. Rode exercicio9_rate_limit_anomalia.py em outro terminal.
    2. Rode este script.

Nota: como ambos os "IPs" de teste batem no mesmo servidor local, o Flask
vai enxergar os dois como 127.0.0.1 (o mesmo IP de origem) a menos que o
teste seja rodado de fato de duas máquinas/interfaces diferentes. Para
fins didáticos, este script simula os dois perfis de tráfego (normal e
hostil) e a distinção real entre IPs pode ser adaptada rodando os testes
a partir de containers/VMs diferentes, ou passando um cabeçalho
X-Forwarded-For customizado se o Flask for configurado para confiar nele.
"""

import time

import requests

BASE_URL = "http://localhost:5000"


def trafego_normal():
    print("Gerando tráfego normal (5 requisições espaçadas)...")
    for _ in range(5):
        r = requests.get(f"{BASE_URL}/api/ping")
        print(f"  GET /api/ping -> {r.status_code}")
        time.sleep(1)


def trafego_hostil():
    print("Gerando tráfego hostil (60 requisições em rajada, várias para rotas inexistentes)...")
    for i in range(60):
        if i % 3 == 0:
            r = requests.get(f"{BASE_URL}/rota-que-nao-existe-{i}")
        else:
            r = requests.get(f"{BASE_URL}/api/dados")
        if i % 10 == 0:
            print(f"  requisição {i}: {r.status_code}")


def disparar_analise():
    print("\nDisparando análise de anomalias...")
    r = requests.post(f"{BASE_URL}/admin/analisar")
    print(r.json())


def testar_bloqueio():
    print("\nTestando se o tráfego subsequente leva 429...")
    r = requests.get(f"{BASE_URL}/api/ping")
    print(f"Próxima requisição -> {r.status_code}")
    if r.status_code == 429:
        print(f"  corpo: {r.json()} | Retry-After: {r.headers.get('Retry-After')}")


if __name__ == "__main__":
    trafego_normal()
    trafego_hostil()
    disparar_analise()
    testar_bloqueio()
