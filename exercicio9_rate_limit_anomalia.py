"""
Exercício 9 — Rate limiting guiado por anomalia (Aulas 2, 4, 6 e 8/A09)

Pré-requisitos:
    pip install flask pymongo scikit-learn numpy requests
    - MongoDB rodando em localhost:27017

Como rodar:
    Terminal 1: python exercicio9_rate_limit_anomalia.py
    Terminal 2: python exercicio9_teste_carga.py   (script de teste abaixo,
                gerado como arquivo separado)

Fluxo:
  1. before_request grava {ip, rota, metodo, timestamp} em `acessos`.
  2. after_request completa o registro com o status code da resposta.
  3. Uma rota /admin/analisar roda a agregação + IsolationForest e marca
     quais IPs são anômalos, guardando o resultado em memória.
  4. before_request também checa se o IP já foi marcado como anômalo;
     se sim, responde 429 direto, sem nem chegar na rota normal.
"""

from datetime import datetime, timedelta

import numpy as np
from flask import Flask, g, jsonify, request
from pymongo import MongoClient
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "seguranca"

ips_bloqueados = set()


def conectar_mongo():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


@app.before_request
def checar_bloqueio_e_iniciar_registro():
    ip = request.remote_addr or "desconhecido"
    g.inicio = datetime.now()

    if ip in ips_bloqueados:
        resp = jsonify({"erro": "muitas requisições"})
        resp.status_code = 429
        resp.headers["Retry-After"] = "60"
        return resp


@app.after_request
def registrar_acesso(response):
    ip = request.remote_addr or "desconhecido"
    db = conectar_mongo()
    db.acessos.insert_one({
        "ip": ip,
        "rota": request.path,
        "metodo": request.method,
        "status": response.status_code,
        "timestamp": g.get("inicio", datetime.now()),
    })
    return response


@app.route("/api/ping")
def ping():
    return jsonify({"pong": True}), 200


@app.route("/api/dados")
def dados():
    return jsonify({"dados": [1, 2, 3]}), 200


def _agregar_comportamento_por_ip(db, janela_segundos=15):
    limite = datetime.now() - timedelta(seconds=janela_segundos)
    pipeline = [
        {"$match": {"timestamp": {"$gte": limite}}},
        {
            "$group": {
                "_id": "$ip",
                "total_requisicoes": {"$sum": 1},
                "total_4xx": {
                    "$sum": {"$cond": [{"$and": [{"$gte": ["$status", 400]}, {"$lt": ["$status", 500]}]}, 1, 0]}
                },
                "rotas_distintas": {"$addToSet": "$rota"},
                "primeiro": {"$min": "$timestamp"},
                "ultimo": {"$max": "$timestamp"},
            }
        },
    ]
    return list(db.acessos.aggregate(pipeline))


@app.route("/admin/analisar", methods=["POST"])
def analisar():
    global ips_bloqueados

    db = conectar_mongo()
    agregados = _agregar_comportamento_por_ip(db)

    if len(agregados) < 2:
        return jsonify({"aviso": "poucos IPs distintos para detectar anomalia com confiança"}), 200

    ips = []
    features = []
    resumo = []

    for doc in agregados:
        duracao_min = max((doc["ultimo"] - doc["primeiro"]).total_seconds() / 60.0, 1 / 60)
        req_por_minuto = doc["total_requisicoes"] / duracao_min
        taxa_4xx = doc["total_4xx"] / doc["total_requisicoes"]
        rotas_distintas = len(doc["rotas_distintas"])

        ips.append(doc["_id"])
        features.append([req_por_minuto, taxa_4xx, rotas_distintas])
        resumo.append({
            "ip": doc["_id"],
            "req_por_minuto": round(req_por_minuto, 2),
            "taxa_4xx": round(taxa_4xx, 2),
            "rotas_distintas": rotas_distintas,
        })

    X = np.array(features)
    clf = IsolationForest(contamination=0.2, random_state=42)
    rotulos = clf.fit_predict(X)  # -1 = anômalo, 1 = normal

    novos_bloqueados = set()
    print("=== Análise de acessos ===")
    for ip, dados_ip, rotulo in zip(ips, resumo, rotulos):
        classificacao = "ANOMALIA -> bloqueado" if rotulo == -1 else "normal"
        print(
            f"{ip:15s} [{dados_ip['req_por_minuto']:6.1f} req/min | "
            f"4xx {dados_ip['taxa_4xx']:.2f} | {dados_ip['rotas_distintas']} rotas]  -> {classificacao}"
        )
        if rotulo == -1:
            novos_bloqueados.add(ip)

    ips_bloqueados = novos_bloqueados

    return jsonify({
        "analisados": resumo,
        "bloqueados": list(ips_bloqueados),
    }), 200


if __name__ == "__main__":
    conectar_mongo().acessos.drop()
    app.run(debug=True, host="0.0.0.0", port=5000)
