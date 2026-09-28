"""
Exercício 2 — Migração relacional -> documentos (Aulas 1, 2 e 3)

Pré-requisitos para rodar:
    pip install mysql-connector-python pymongo
    - MySQL rodando em localhost (ajuste host/user/password/database abaixo)
    - MongoDB rodando em localhost:27017

O script:
  1. Cria e popula as tabelas `ativos` e `alertas` no MySQL.
  2. Lê os dados com um JOIN parametrizado.
  3. Monta documentos aninhados (dados do ativo dentro de cada alerta)
     e insere no MongoDB com insert_many.
  4. Verifica a migração comparando as contagens MySQL x MongoDB.
  5. Executa uma consulta sem JOIN no Mongo para provar o ganho.
"""

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


def conectar_mysql():
    return mysql.connector.connect(**MYSQL_CONFIG)


def conectar_mongo():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


def criar_e_popular_mysql(con):
    cur = con.cursor()

    cur.execute("DROP TABLE IF EXISTS alertas")
    cur.execute("DROP TABLE IF EXISTS ativos")

    cur.execute("""
        CREATE TABLE ativos (
            id INT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            ip VARCHAR(45) UNIQUE NOT NULL,
            criticidade ENUM('baixa', 'media', 'alta') NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE alertas (
            id INT PRIMARY KEY,
            ativo_id INT NOT NULL,
            tipo VARCHAR(50) NOT NULL,
            severidade VARCHAR(20) NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (ativo_id) REFERENCES ativos(id)
        )
    """)

    ativos = [
        (1, "SRV-WEB01", "192.168.1.10", "alta"),
        (2, "PC-RH03", "192.168.1.45", "baixa"),
    ]
    alertas = [
        (1, 1, "BRUTE_FORCE", "critica"),
        (2, 1, "PORT_SCAN", "alta"),
        (3, 2, "XSS", "media"),
    ]

    cur.executemany(
        "INSERT INTO ativos (id, nome, ip, criticidade) VALUES (%s, %s, %s, %s)",
        ativos,
    )
    cur.executemany(
        "INSERT INTO alertas (id, ativo_id, tipo, severidade) VALUES (%s, %s, %s, %s)",
        alertas,
    )
    con.commit()
    cur.close()


def ler_com_join(con):
    """Lê todos os alertas com os dados do ativo já embutidos, via JOIN parametrizado."""
    cur = con.cursor(dictionary=True)
    # A query não recebe parâmetro externo aqui, mas o padrão parametrizado
    # (execute com tupla de argumentos) é o que se usaria caso houvesse filtro.
    cur.execute("""
        SELECT a.id AS alerta_id, a.tipo, a.severidade,
               t.nome AS ativo_nome, t.ip AS ativo_ip, t.criticidade AS ativo_criticidade
        FROM alertas a
        JOIN ativos t ON t.id = a.ativo_id
        WHERE 1 = %s
    """, (1,))
    linhas = cur.fetchall()
    cur.close()
    return linhas


def montar_documentos(linhas):
    documentos = []
    for linha in linhas:
        documentos.append({
            "tipo": linha["tipo"],
            "severidade": linha["severidade"],
            "ativo": {
                "nome": linha["ativo_nome"],
                "ip": linha["ativo_ip"],
                "criticidade": linha["ativo_criticidade"],
            },
        })
    return documentos


def migrar():
    con = conectar_mysql()
    criar_e_popular_mysql(con)

    linhas = ler_com_join(con)
    documentos = montar_documentos(linhas)

    db = conectar_mongo()
    db.alertas.drop()
    db.alertas.insert_many(documentos)

    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM alertas")
    total_mysql = cur.fetchone()[0]
    cur.close()
    con.close()

    total_mongo = db.alertas.count_documents({})

    status = "MIGRAÇÃO ÍNTEGRA" if total_mysql == total_mongo else "DIVERGÊNCIA DETECTADA"
    print(f"MySQL: {total_mysql} alertas | MongoDB: {total_mongo} documentos -> {status}")

    alta_criticidade = db.alertas.count_documents({"ativo.criticidade": "alta"})
    print(f"Consulta sem JOIN: db.alertas.find({{'ativo.criticidade':'alta'}}) -> {alta_criticidade} documentos")

    print(
        "Comentário: ganha-se leitura direta sem JOIN (o dado do ativo já vem\n"
        "embutido no alerta); perde-se em duplicação — se o nome do ativo\n"
        "mudar, é preciso um update_many em todos os alertas que o referenciam."
    )


if __name__ == "__main__":
    migrar()
