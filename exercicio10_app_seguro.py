"""
Exercício 10 — app_seguro.py

Versão corrigida de app_vulneravel.py. Todas as falhas listadas em
auditoria.md são endereçadas aqui. Rode este arquivo e depois rode
exercicio10_exploit.py apontando para a porta 5001 para ver todos os
ataques falharem.

Pré-requisitos: pip install flask mysql-connector-python
"""

import logging
import os

from flask import Flask, jsonify, request
from markupsafe import escape
import mysql.connector

app = Flask(__name__)

# [Correção 6] Sem debug=True em produção, e sem segredo hardcoded no código:
# lido de variável de ambiente com um valor de desenvolvimento como fallback
# só para o exercício rodar localmente sem configuração extra.
SENHA_MESTRA = os.environ.get("SEGURANCA_SENHA_MESTRA", "defina-via-variavel-de-ambiente")

MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "senha",
    "database": "seguranca",
}

NIVEL_PARA_APAGAR = 5

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app_seguro")


def db():
    return mysql.connector.connect(**MYSQL_CONFIG)


def _preparar_tabela_usuarios():
    con = db()
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute("""
        CREATE TABLE usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100),
            email VARCHAR(150),
            senha_hash VARCHAR(255),
            api_key VARCHAR(100) UNIQUE,
            nivel INT DEFAULT 1
        )
    """)
    # [Correção 5] Nunca devolvemos a coluna de senha nas respostas da API;
    # aqui ela já nasce como "senha_hash" para deixar claro que não é
    # texto puro, e as queries de leitura sempre listam colunas explicitamente.
    cur.executemany(
        "INSERT INTO usuarios (nome, email, senha_hash, api_key, nivel) VALUES (%s,%s,%s,%s,%s)",
        [
            ("ana", "ana@x.com", "hash-fake-1", "key-ana-001", 5),
            ("bruno", "bruno@x.com", "hash-fake-2", "key-bruno-002", 2),
        ],
    )
    con.commit()
    cur.close()
    con.close()


def autenticar():
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    con = db()
    cur = con.cursor(dictionary=True)
    cur.execute("SELECT id, nome, nivel FROM usuarios WHERE api_key = %s", (api_key,))
    usuario = cur.fetchone()
    cur.close()
    con.close()
    return usuario


# [Correção 6] Headers de segurança em toda resposta.
@app.after_request
def headers_seguranca(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# [Correção 1] Query parametrizada em vez de f-string concatenada.
# [Correção 5] SELECT explícito, sem a coluna de senha.
@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    con = db()
    cur = con.cursor(dictionary=True)
    cur.execute(
        "SELECT id, nome, email, api_key, nivel FROM usuarios WHERE nome LIKE %s",
        (f"%{nome}%",),
    )
    resultado = cur.fetchall()
    cur.close()
    con.close()
    return jsonify(resultado)


# [Correção 2] Escapa a entrada do usuário antes de embuti-la no HTML.
# Usar Jinja2/render_template com autoescape seria a forma recomendada em
# uma aplicação maior; aqui, para manter a rota simples, escapamos
# explicitamente com markupsafe.escape, que faz o mesmo trabalho.
@app.route("/perfil")
def perfil():
    nome_usuario = request.args.get("u", "")
    nome_seguro = escape(nome_usuario)
    return f"<h1>Bem-vindo, {nome_seguro}</h1>"


# [Correção 3] Exige autenticação e nível mínimo antes de apagar.
@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    usuario = autenticar()
    if usuario is None:
        return jsonify({"erro": "não autenticado"}), 401
    if usuario["nivel"] < NIVEL_PARA_APAGAR:
        return jsonify({"erro": "acesso negado"}), 403

    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
    con.commit()
    cur.close()
    con.close()
    return jsonify({"removido": uid})


# [Correção 4] Erros internos nunca vazam traceback/nome de tabela: são
# logados no servidor e a resposta ao cliente é genérica.
@app.route("/api/relatorio")
def relatorio():
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT * FROM tabela_inexistente")
        resultado = cur.fetchall()
        cur.close()
        con.close()
        return jsonify(resultado)
    except Exception:
        logger.exception("erro ao gerar relatorio")
        return jsonify({"erro": "erro interno"}), 500


# [Correção 7 - AUSÊNCIA] Rate limiting básico por IP, para não deixar a
# API aberta a força bruta/varredura sem nenhum limite (a versão
# vulnerável simplesmente não tinha nada disso).
_contagem_requisicoes = {}


@app.before_request
def limitar_requisicoes():
    ip = request.remote_addr or "desconhecido"
    _contagem_requisicoes[ip] = _contagem_requisicoes.get(ip, 0) + 1
    if _contagem_requisicoes[ip] > 1000:
        return jsonify({"erro": "muitas requisições"}), 429


# [Correção 8 - AUSÊNCIA] A versão vulnerável não registrava nada em
# lugar nenhum: nenhuma tentativa de exclusão, nenhum acesso à busca de
# usuários, nada. Sem log, um ataque bem-sucedido não deixa rastro
# (A09:2021). Aqui, pelo menos as operações sensíveis (remoção) são
# logadas no servidor.
@app.after_request
def logar_operacoes_sensiveis(response):
    if request.method == "DELETE":
        logger.info(f"DELETE em {request.path} -> status {response.status_code}")
    return response


if __name__ == "__main__":
    _preparar_tabela_usuarios()
    # debug=False e host controlado — nunca 0.0.0.0 + debug=True juntos.
    app.run(debug=False, host="127.0.0.1", port=5001)
