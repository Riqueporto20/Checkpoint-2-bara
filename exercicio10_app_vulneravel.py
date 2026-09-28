"""
Exercício 10 — app_vulneravel.py

Cópia local, inalterada, da API vulnerável fornecida no enunciado.
Existe SOMENTE para o exploit.py ser demonstrado contra ela em ambiente
de laboratório. Não exponha isso em rede alguma além de localhost.

Pré-requisitos: pip install flask mysql-connector-python
"""

from flask import Flask, request, jsonify
import mysql.connector

app = Flask(__name__)
SENHA_MESTRA = "Cyber@2024"

MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "senha",
    "database": "seguranca",
}


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
            senha VARCHAR(255),
            nivel INT DEFAULT 1
        )
    """)
    cur.executemany(
        "INSERT INTO usuarios (nome, email, senha, nivel) VALUES (%s,%s,%s,%s)",
        [
            ("ana", "ana@x.com", "senha123", 5),
            ("bruno", "bruno@x.com", "outrasenha", 2),
            ("caio", "caio@x.com", "123456", 1),
        ],
    )
    con.commit()
    cur.close()
    con.close()


@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    cur = db().cursor(dictionary=True)
    cur.execute(f"SELECT * FROM usuarios WHERE nome LIKE '%{nome}%'")
    return jsonify(cur.fetchall())


@app.route("/perfil")
def perfil():
    return f"<h1>Bem-vindo, {request.args.get('u','')}</h1>"


@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    con = db()
    cur = con.cursor()
    cur.execute("DELETE FROM usuarios WHERE id = %s", (uid,))
    con.commit()
    return jsonify({"removido": uid})


@app.route("/api/relatorio")
def relatorio():
    cur = db().cursor()
    cur.execute("SELECT * FROM tabela_inexistente")
    return jsonify(cur.fetchall())


if __name__ == "__main__":
    _preparar_tabela_usuarios()
    app.run(debug=True, host="0.0.0.0", port=5000)
