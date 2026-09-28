"""
Exercício 4 — Transação com trilha de auditoria (Aulas 2, 3 e 8/A09)

Pré-requisitos:
    pip install mysql-connector-python pymongo
    - MySQL rodando em localhost
    - MongoDB rodando em localhost:27017

Regra de ouro do exercício: TODA tentativa de alterar_nivel vira um
registro de auditoria no Mongo, seja ela aceita ou recusada. Um ataque
que falha e não deixa rastro é, na prática, um ataque invisível (A09).
"""

from datetime import datetime

import mysql.connector
from pymongo import MongoClient

MYSQL_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "senha",
    "database": "seguranca",
}

MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "seguranca"

NIVEL_MINIMO_PARA_ALTERAR = 5


def conectar_mysql():
    return mysql.connector.connect(**MYSQL_CONFIG)


def conectar_mongo():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


def criar_e_popular_usuarios(con):
    cur = con.cursor()
    cur.execute("DROP TABLE IF EXISTS usuarios")
    cur.execute("""
        CREATE TABLE usuarios (
            id INT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL,
            nivel_acesso INT NOT NULL
        )
    """)
    usuarios = [
        (1, "ana", "ana@x.com", 5),
        (2, "bruno", "bruno@x.com", 2),
        (3, "caio", "caio@x.com", 1),
    ]
    cur.executemany(
        "INSERT INTO usuarios (id, nome, email, nivel_acesso) VALUES (%s, %s, %s, %s)",
        usuarios,
    )
    con.commit()
    cur.close()


def _registrar_auditoria(colecao_auditoria, quem, alvo, nivel_anterior, nivel_novo, resultado, motivo=None):
    doc = {
        "quem": quem,
        "alvo": alvo,
        "nivel_anterior": nivel_anterior,
        "nivel_novo": nivel_novo,
        "resultado": resultado,
        "timestamp": datetime.now(),
    }
    if motivo:
        doc["motivo"] = motivo
    colecao_auditoria.insert_one(doc)


def alterar_nivel(con, colecao_auditoria, admin_id: int, alvo_id: int, novo_nivel: int) -> dict:
    """
    Altera o nivel_acesso de `alvo_id` para `novo_nivel`, se `admin_id`
    tiver privilégio suficiente. A operação roda dentro de uma transação
    MySQL (commit em sucesso, rollback em qualquer recusa/erro), e toda
    tentativa — aceita ou recusada — é registrada na trilha de auditoria.
    """
    cur = con.cursor(dictionary=True)

    try:
        con.start_transaction()

        # Busca o admin.
        cur.execute("SELECT nivel_acesso FROM usuarios WHERE id = %s", (admin_id,))
        admin = cur.fetchone()

        if admin is None:
            con.rollback()
            _registrar_auditoria(colecao_auditoria, admin_id, alvo_id, None, novo_nivel,
                                  "RECUSADO", motivo="admin inexistente")
            return {"ok": False, "motivo": "admin inexistente"}

        if admin["nivel_acesso"] < NIVEL_MINIMO_PARA_ALTERAR:
            con.rollback()
            _registrar_auditoria(colecao_auditoria, admin_id, alvo_id, None, novo_nivel,
                                  "RECUSADO", motivo="admin sem privilégio")
            return {"ok": False, "motivo": "admin sem privilégio"}

        if admin_id == alvo_id:
            con.rollback()
            _registrar_auditoria(colecao_auditoria, admin_id, alvo_id, admin["nivel_acesso"],
                                  novo_nivel, "RECUSADO", motivo="auto-promoção")
            return {"ok": False, "motivo": "auto-promoção"}

        # Busca o alvo (para registrar o nível anterior e confirmar que existe).
        cur.execute("SELECT nivel_acesso FROM usuarios WHERE id = %s", (alvo_id,))
        alvo = cur.fetchone()

        if alvo is None:
            con.rollback()
            _registrar_auditoria(colecao_auditoria, admin_id, alvo_id, None, novo_nivel,
                                  "RECUSADO", motivo="alvo inexistente")
            return {"ok": False, "motivo": "alvo inexistente"}

        nivel_anterior = alvo["nivel_acesso"]

        cur.execute("UPDATE usuarios SET nivel_acesso = %s WHERE id = %s", (novo_nivel, alvo_id))
        con.commit()

        _registrar_auditoria(colecao_auditoria, admin_id, alvo_id, nivel_anterior,
                              novo_nivel, "OK")
        return {"ok": True, "nivel_anterior": nivel_anterior, "nivel_novo": novo_nivel}

    except Exception as exc:
        con.rollback()
        _registrar_auditoria(colecao_auditoria, admin_id, alvo_id, None, novo_nivel,
                              "RECUSADO", motivo=f"erro inesperado: {exc}")
        return {"ok": False, "motivo": f"erro inesperado: {exc}"}
    finally:
        cur.close()


def main():
    con = conectar_mysql()
    criar_e_popular_usuarios(con)

    db = conectar_mongo()
    db.auditoria.drop()

    testes = [
        (1, 2, 4),   # OK esperado
        (2, 3, 5),   # RECUSADO: admin sem privilégio
        (1, 1, 9),   # RECUSADO: auto-promoção
        (1, 99, 3),  # RECUSADO: alvo inexistente
    ]

    for admin_id, alvo_id, novo_nivel in testes:
        resultado = alterar_nivel(con, db.auditoria, admin_id, alvo_id, novo_nivel)
        print(f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> {resultado}")

    total = db.auditoria.count_documents({})
    recusados = db.auditoria.count_documents({"resultado": "RECUSADO"})
    print(f"\nTrilha de auditoria ao final: {total} documentos")
    print(f"db.auditoria.count_documents({{'resultado':'RECUSADO'}}) -> {recusados}")

    con.close()


if __name__ == "__main__":
    main()
