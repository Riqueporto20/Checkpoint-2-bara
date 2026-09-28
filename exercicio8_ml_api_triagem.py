"""
Exercício 8 — Modelo de ML servido por API, com métricas auditáveis
(Aulas 2, 4, 6 e 7)

Pré-requisitos:
    pip install flask scikit-learn numpy pymongo
    - MongoDB rodando em localhost:27017

Execute com: python exercicio8_ml_api_triagem.py

Testes manuais:
    curl -X POST -H "Content-Type: application/json" \
         -d '{"features":[12,7,90000,3]}' http://localhost:5000/api/triagem
    curl -X POST -H "Content-Type: application/json" \
         -d '{"features":[0,1,1200,14]}' http://localhost:5000/api/triagem
    curl -X POST -H "Content-Type: application/json" \
         -d '{"features":[12,7,90000]}' http://localhost:5000/api/triagem
    curl -X POST -H "Content-Type: application/json" \
         -d '{"features":["12","sete",0,3]}' http://localhost:5000/api/triagem
    curl -X POST http://localhost:5000/api/triagem
    curl http://localhost:5000/api/modelo/metricas

Ponto central: a entrada do modelo é entrada de usuário. Um POST malformado
não pode derrubar o processo com um 500 nem, pior, ser passado direto para
o modelo — todo formato e tipo é validado antes de qualquer predict().
"""

from datetime import datetime

import numpy as np
from flask import Flask, jsonify, request
from pymongo import MongoClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

app = Flask(__name__)

MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "seguranca"

NUM_FEATURES = 4  # [falhas_login, portas_distintas, bytes_saida, hora_do_dia]

modelo = None
metricas_cache = None


def conectar_mongo():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


def gerar_dataset_sintetico(n=400, seed=42):
    """
    Gera um dataset sintético plausível: risco "alto" tende a ter mais
    falhas de login, mais portas distintas escaneadas e mais bytes de
    saída (exfiltração), risco "baixo" é tráfego normal.
    """
    rng = np.random.default_rng(seed)
    metade = n // 2

    # Classe "baixo risco" (rótulo 0)
    falhas_baixo = rng.integers(0, 3, metade)
    portas_baixo = rng.integers(1, 3, metade)
    bytes_baixo = rng.integers(500, 5000, metade)
    hora_baixo = rng.integers(6, 22, metade)

    # Classe "alto risco" (rótulo 1)
    falhas_alto = rng.integers(5, 20, metade)
    portas_alto = rng.integers(4, 15, metade)
    bytes_alto = rng.integers(20000, 150000, metade)
    hora_alto = rng.integers(0, 6, metade)

    X = np.vstack([
        np.column_stack([falhas_baixo, portas_baixo, bytes_baixo, hora_baixo]),
        np.column_stack([falhas_alto, portas_alto, bytes_alto, hora_alto]),
    ])
    y = np.array([0] * metade + [1] * metade)

    return X, y


def treinar_modelo():
    global modelo, metricas_cache

    X, y = gerar_dataset_sintetico()
    X_treino, X_teste, y_treino, y_teste = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    modelo = RandomForestClassifier(n_estimators=100, random_state=42)
    modelo.fit(X_treino, y_treino)

    y_pred = modelo.predict(X_teste)

    metricas_cache = {
        "precisao": round(float(precision_score(y_teste, y_pred)), 4),
        "recall": round(float(recall_score(y_teste, y_pred)), 4),
        "f1": round(float(f1_score(y_teste, y_pred)), 4),
        "matriz": confusion_matrix(y_teste, y_pred).tolist(),
    }


def validar_features(corpo):
    """
    Retorna (features_validas, erro). Se erro não for None, features é None.
    Nenhuma exceção deve escapar daqui — tudo vira uma mensagem de erro
    tratada, nunca um 500.
    """
    if not corpo or "features" not in corpo:
        return None, "corpo da requisição deve conter 'features'"

    features = corpo["features"]

    if not isinstance(features, list):
        return None, "'features' deve ser uma lista"

    if len(features) != NUM_FEATURES:
        return None, f"esperadas {NUM_FEATURES} features, recebidas {len(features)}"

    for valor in features:
        if isinstance(valor, bool) or not isinstance(valor, (int, float)):
            return None, "features devem ser numéricas"

    return [float(v) for v in features], None


@app.route("/api/triagem", methods=["POST"])
def triagem():
    corpo = request.get_json(silent=True)

    features, erro = validar_features(corpo)
    if erro is not None:
        return jsonify({"erro": erro}), 400

    entrada = np.array([features])
    predicao = modelo.predict(entrada)[0]
    probabilidades = modelo.predict_proba(entrada)[0]
    confianca = float(max(probabilidades))

    risco = "alto" if predicao == 1 else "baixo"

    db = conectar_mongo()
    db.previsoes.insert_one({
        "entrada": features,
        "saida": risco,
        "confianca": confianca,
        "timestamp": datetime.now(),
    })

    return jsonify({"risco": risco, "confianca": round(confianca, 4)}), 200


@app.route("/api/modelo/metricas", methods=["GET"])
def metricas():
    resposta = dict(metricas_cache)
    resposta["aviso"] = (
        "a acurácia foi omitida de propósito: em um dataset de triagem de "
        "risco, as classes costumam ser desbalanceadas (poucos eventos de "
        "alto risco no dia a dia), e a acurácia isolada esconde um modelo "
        "que simplesmente chuta 'baixo risco' sempre — precisão, recall e "
        "F1 mostram melhor como o modelo se comporta na classe rara"
    )
    return jsonify(resposta), 200


if __name__ == "__main__":
    treinar_modelo()
    conectar_mongo().previsoes.drop()
    app.run(debug=True, host="0.0.0.0")
