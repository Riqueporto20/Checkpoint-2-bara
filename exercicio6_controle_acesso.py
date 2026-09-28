"""
Exercício 6 — Controle de acesso quebrado (Aulas 3, 6 e 8/A01)

Pré-requisitos:
    pip install flask mysql-connector-python
    - MySQL rodando em localhost, banco `seguranca`

Execute com: python exercicio6_controle_acesso.py

Testes manuais (ver matriz completa no enunciado):
    curl -H "X-API-Key: key-ana-001" http://localhost:5000/api/incidentes/1
    curl -H "X-API-Key: key-bruno-002" http://localhost:5000/api/incidentes/1
    curl http://localhost:5000/api/incidentes/1
    curl -H "X-API-Key: key-inexistente" http://localhost:5000/api/incidentes/1
    curl -H "X-API-Key: key-bruno-002" http://localhost:5000/api/incidentes
    curl -X DELETE -H "X-API-Key: key-ana-001" http://localhost:5000/api/incidentes/2
    curl -X DELETE -H "X-API-Key: key-bruno-002" http://localhost:5000/api/incidentes/1
    curl -H "X-API-Key: key-ana-001" http://localhost:5000/api/incidentes/999

Distinção central do exercício:
    401 Unauthorized -> "não sei quem você é" (sem header, ou chave que
        não bate com nenhum registro no banco).
    403 Forbidden    -> "sei exatamente quem você é, e mesmo assim você
        não pode fazer isso" (IDOR barrado, ou nível insuficiente).
O corpo do 403 nunca revela se o recurso existe — sempre a mesma mensagem
genérica, senão a resposta vira um oráculo de enumeração de IDs.
"""

import mysql.connector
from flask import Flask, jsonify, request, g

app = Flask(__name__)

MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "senha",
    "database": "seguranca",
}

NIVEL_PARA_APAGAR_QUALQUER = 5


def conectar():
    return mysql.connector.connect(**MYSQL_CONFIG)


def _preparar_tabelas(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS incidentes")
    cur.execute("DROP TABLE IF EXISTS analistas")

    cur.execute("""
        CREATE TABLE analistas (
            id INT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            api_key VARCHAR(100) UNIQUE NOT NULL,
            nivel INT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE incidentes (
            id INT PRIMARY KEY,
            dono_id INT NOT NULL,
            titulo VARCHAR(200) NOT NULL,
            severidade VARCHAR(20) NOT NULL,
            status VARCHAR(20) DEFAULT 'aberto',
            FOREIGN KEY (dono_id) REFERENCES analistas(id)
        )
    """)

    analistas = [(1, "ana", "key-ana-001", 5), (2, "bruno", "key-bruno-002", 2)]
    incidentes = [(1, 1, "Brute force SSH", "critica"), (2, 2, "Phishing no RH", "media")]

    cur.executemany(
        "INSERT INTO analistas (id, nome, api_key, nivel) VALUES (%s, %s, %s, %s)",
        analistas,
    )
    cur.executemany(
        "INSERT INTO incidentes (id, dono_id, titulo, severidade) VALUES (%s, %s, %s, %s)",
        incidentes,
    )
    con.commit()
    cur.close()


def autenticar():
    """
    Retorna o analista autenticado (dict) ou None. Não decide autorização
    aqui — só resolve "quem é você", usando sempre query parametrizada.
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None

    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute("SELECT id, nome, nivel FROM analistas WHERE api_key = %s", (api_key,))
    analista = cur.fetchone()
    cur.close()
    con.close()
    return analista


@app.before_request
def carregar_analista():
    g.analista = autenticar()


def _buscar_incidente(incidente_id):
    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute("SELECT * FROM incidentes WHERE id = %s", (incidente_id,))
    incidente = cur.fetchone()
    cur.close()
    con.close()
    return incidente


@app.route("/api/incidentes/<int:incidente_id>", methods=["GET"])
def ver_incidente(incidente_id):
    if g.analista is None:
        return jsonify({"erro": "não autenticado"}), 401

    incidente = _buscar_incidente(incidente_id)
    if incidente is None:
        return jsonify({"erro": "não encontrado"}), 404

    eh_dono = incidente["dono_id"] == g.analista["id"]
    if not eh_dono:
        # Mensagem genérica: não confirma nem nega que o incidente existe
        # além de dizer que o acesso foi negado.
        return jsonify({"erro": "acesso negado"}), 403

    return jsonify(incidente), 200


@app.route("/api/incidentes", methods=["GET"])
def listar_incidentes():
    if g.analista is None:
        return jsonify({"erro": "não autenticado"}), 401

    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute("SELECT * FROM incidentes WHERE dono_id = %s", (g.analista["id"],))
    incidentes = cur.fetchall()
    cur.close()
    con.close()

    return jsonify(incidentes), 200


@app.route("/api/incidentes/<int:incidente_id>", methods=["DELETE"])
def apagar_incidente(incidente_id):
    if g.analista is None:
        return jsonify({"erro": "não autenticado"}), 401

    if g.analista["nivel"] < NIVEL_PARA_APAGAR_QUALQUER:
        return jsonify({"erro": "acesso negado"}), 403

    incidente = _buscar_incidente(incidente_id)
    if incidente is None:
        return jsonify({"erro": "não encontrado"}), 404

    con = conectar()
    cur = con.cursor()
    cur.execute("DELETE FROM incidentes WHERE id = %s", (incidente_id,))
    con.commit()
    cur.close()
    con.close()

    return jsonify({"removido": incidente_id}), 200


if __name__ == "__main__":
    con = conectar()
    _preparar_tabelas(con)
    con.close()
    app.run(debug=True, host="0.0.0.0")
