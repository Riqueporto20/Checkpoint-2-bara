"""
Exercício 3 — Retenção e janela temporal (Aula 2)

Pré-requisitos:
    pip install pymongo
    - MongoDB rodando em localhost:27017

O script:
  1. Cria a coleção `eventos` com um índice TTL de 7 dias.
  2. Popula 200 eventos com timestamps espalhados nas últimas 24 horas,
     marcando parte deles como falhas.
  3. Usa agregação para calcular a distribuição de falhas por hora do dia.
  4. Imprime um "gráfico" de barras em texto e destaca o horário de pico.

Nota: o TTL do MongoDB roda em um processo em background a cada ~60s,
então documentos expirados não somem instantaneamente — isso é esperado
e não é bug.
"""

import random
from datetime import datetime, timedelta

from pymongo import MongoClient

MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "seguranca"


def conectar_mongo():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


def criar_indice_ttl(colecao):
    # expireAfterSeconds=604800 -> 7 dias. O Mongo remove automaticamente
    # documentos cujo campo `timestamp` já passou desse limite.
    colecao.create_index("timestamp", expireAfterSeconds=604800)


def popular_eventos(colecao, quantidade=200):
    colecao.delete_many({})

    agora = datetime.now()
    eventos = []
    for _ in range(quantidade):
        offset_segundos = random.randint(0, 24 * 3600)
        timestamp = agora - timedelta(seconds=offset_segundos)
        # ~30% de chance de ser uma falha, mas concentramos mais falhas
        # entre 2h e 4h para simular um horário de ataque automatizado.
        hora = timestamp.hour
        prob_falha = 0.6 if 2 <= hora <= 4 else 0.15
        eh_falha = random.random() < prob_falha

        eventos.append({
            "timestamp": timestamp,
            "tipo": "LOGIN_FALHA" if eh_falha else "LOGIN_OK",
            "falha": eh_falha,
        })

    colecao.insert_many(eventos)


def falhas_por_hora(colecao):
    pipeline = [
        {"$match": {"falha": True}},
        {"$group": {"_id": {"$hour": "$timestamp"}, "total": {"$sum": 1}}},
        {"$sort": {"_id": 1}},
    ]
    resultado = list(colecao.aggregate(pipeline))
    return {doc["_id"]: doc["total"] for doc in resultado}


def eventos_na_janela(colecao, horas=6):
    limite = datetime.now() - timedelta(hours=horas)
    return colecao.count_documents({"timestamp": {"$gte": limite}})


def imprimir_grafico(distribuicao):
    print("=== Falhas por hora (últimas 24h) ===")
    if not distribuicao:
        print("Nenhuma falha registrada.")
        return

    pico_hora = max(distribuicao, key=distribuicao.get)
    pico_total = distribuicao[pico_hora]

    for hora in sorted(distribuicao):
        total = distribuicao[hora]
        barra = "█" * total
        marcador = "  <- pico" if hora == pico_hora else ""
        print(f"{hora:02d}h | {barra} {total}{marcador}")

    print(f"Hora de pico: {pico_hora:02d}h ({pico_total} falhas)")


def main():
    db = conectar_mongo()
    eventos = db.eventos

    criar_indice_ttl(eventos)
    popular_eventos(eventos, quantidade=200)

    distribuicao = falhas_por_hora(eventos)
    imprimir_grafico(distribuicao)

    total_janela = eventos_na_janela(eventos, horas=6)
    print(f"Eventos nas últimas 6h: {total_janela}")

    print("Índice TTL ativo: eventos com mais de 7 dias serão removidos automaticamente.")
    print(
        "Comentário: o TTL é uma decisão de segurança porque logs antigos demais "
        "viram passivo (custo de armazenamento e superfície de vazamento) sem "
        "mais valor de investigação — reter para sempre não é sinônimo de mais seguro."
    )


if __name__ == "__main__":
    main()
