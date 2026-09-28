"""
Exercício 5 — O ORDER BY que o %s não protege (Aulas 3, 6, 7 e 8/A05)

Pré-requisitos:
    pip install flask mysql-connector-python
    - MySQL rodando em localhost, banco `seguranca`

Execute com: python exercicio5_orderby_whitelist.py
Depois teste com, por exemplo:
    curl "http://localhost:5000/api/eventos?ordenar_por=sev&ordem=desc&tamanho=5"
    curl "http://localhost:5000/api/eventos?ordenar_por=criado_em,(SELECT+1)&ordem=asc"
    curl "http://localhost:5000/api/eventos?tamanho=abc"
    curl "http://localhost:5000/api/eventos?tamanho=100000"

O ponto central: `%s` (placeholder do driver) parametriza VALORES, não
IDENTIFICADORES (nomes de coluna/tabela). O driver escapa o valor como
uma string/número dentro da query, mas um identificador precisa aparecer
"nu" no SQL — não há como o driver diferenciar "nome de coluna válido"
de "nome de coluna + injeção" nesse contexto. Por isso a única defesa
sólida é uma whitelist fechada: o valor que vem da URL nunca toca a
query diretamente, ele é usado só para escolher uma chave num dicionário
de valores pré-aprovados.
"""

import mysql.connector
from flask import Flask, jsonify, request

app = Flask(__name__)

MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "senha",
    "database": "seguranca",
}

# Mapa fechado: só o que está aqui pode virar SQL. Qualquer outra coisa
# vinda da URL é rejeitada antes de chegar perto do banco.
COLUNAS = {"data": "criado_em", "sev": "severidade", "ip": "ip_origem"}
ORDEM = {"asc": "ASC", "desc": "DESC"}
TAMANHO_MAXIMO = 100
TAMANHO_PADRAO = 20


def conectar():
    return mysql.connector.connect(**MYSQL_CONFIG)


def _preparar_tabela_eventos(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS eventos")
    cur.execute("""
        CREATE TABLE eventos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_origem VARCHAR(45),
            severidade VARCHAR(20),
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    dados = [
        ("192.168.1.10", "critica"),
        ("192.168.1.11", "alta"),
        ("192.168.1.12", "media"),
        ("192.168.1.13", "baixa"),
        ("192.168.1.14", "alta"),
        ("192.168.1.15", "critica"),
    ]
    cur.executemany("INSERT INTO eventos (ip_origem, severidade) VALUES (%s, %s)", dados)
    con.commit()
    cur.close()


@app.route("/api/eventos")
def listar_eventos():
    ordenar_por = request.args.get("ordenar_por", "data")
    ordem = request.args.get("ordem", "asc")
    tamanho_raw = request.args.get("tamanho", str(TAMANHO_PADRAO))

    # 1. Valida a coluna contra a whitelist. Nada do que vier na URL é
    #    concatenado diretamente na query; usamos só para indexar o dict.
    coluna_sql = COLUNAS.get(ordenar_por)
    if coluna_sql is None:
        return jsonify({"erro": "campo de ordenação inválido"}), 400

    ordem_sql = ORDEM.get(ordem.lower())
    if ordem_sql is None:
        return jsonify({"erro": "ordem inválida"}), 400

    # 2. Valida o tamanho como inteiro antes de qualquer uso.
    try:
        tamanho = int(tamanho_raw)
    except ValueError:
        return jsonify({"erro": "tamanho deve ser inteiro"}), 400

    if tamanho <= 0:
        return jsonify({"erro": "tamanho deve ser positivo"}), 400

    tamanho = min(tamanho, TAMANHO_MAXIMO)

    # 3. A query final usa identificadores só da whitelist (nunca da URL
    #    diretamente) e usa `%s` apenas para o valor (LIMIT), que é dado,
    #    não identificador — aí sim o placeholder protege de verdade.
    query = f"SELECT * FROM eventos ORDER BY {coluna_sql} {ordem_sql} LIMIT %s"

    con = conectar()
    cur = con.cursor(dictionary=True)
    cur.execute(query, (tamanho,))
    linhas = cur.fetchall()
    cur.close()
    con.close()

    # datetime não é serializável por padrão em JSON.
    for linha in linhas:
        if "criado_em" in linha and linha["criado_em"] is not None:
            linha["criado_em"] = linha["criado_em"].isoformat()

    return jsonify(linhas), 200


if __name__ == "__main__":
    con = conectar()
    _preparar_tabela_eventos(con)
    con.close()
    app.run(debug=True, host="0.0.0.0")
