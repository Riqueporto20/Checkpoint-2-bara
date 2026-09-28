"""
Exercício 7 — XSS onde ninguém procura: dentro do atributo (Aulas 6, 7 e 8/A05)

Pré-requisitos:
    pip install flask pymongo
    - MongoDB rodando em localhost:27017

Execute com: python exercicio7_xss_atributo.py
Depois abra no navegador:
    http://localhost:5000/dashboard            (versão segura)
    http://localhost:5000/dashboard-inseguro    (versão vulnerável, para comparação)

⚠️ Exercício defensivo: os payloads abaixo rodam apenas contra esta
aplicação local, para fins de estudo.
"""

from flask import Flask, render_template_string
from markupsafe import Markup
from pymongo import MongoClient

app = Flask(__name__)

MONGO_URI = "mongodb://localhost:27017"
MONGO_DB = "seguranca"

P1 = "<script>alert('xss1')</script>"
P2 = 'x" onerror="alert(\'xss2\')'


def conectar_mongo():
    client = MongoClient(MONGO_URI)
    return client[MONGO_DB]


def popular_incidentes():
    db = conectar_mongo()
    db.incidentes_dashboard.drop()
    db.incidentes_dashboard.insert_many([
        {"titulo": "Tentativa de acesso suspeita", "ativo": P1},
        {"titulo": "Varredura de portas", "ativo": P2},
    ])
    return db


# --- Versão SEGURA -----------------------------------------------------
#
# Jinja2 faz auto-escape por padrão em arquivos .html renderizados com
# render_template, e também com render_template_string quando o Flask
# está configurado normalmente (autoescape=True para .html). Isso escapa
# `<`, `>`, `"` etc. tanto no texto da célula quanto dentro do atributo
# `alt`, então nenhum dos dois payloads consegue "fechar" a tag ou o
# atributo em que foram inseridos.
#
# O único jeito de reabrir o buraco seria aplicar o filtro `|safe` (ou
# usar Markup diretamente) em cima de uma string que veio do usuário —
# isso desliga o escape justamente no ponto onde ele é mais necessário.

TEMPLATE_SEGURO = """
<!doctype html>
<html>
<head><title>Dashboard (seguro)</title></head>
<body>
  <h1>Incidentes</h1>
  <table border="1">
    <tr><th>Título</th><th>Ícone do ativo</th></tr>
    {% for inc in incidentes %}
    <tr>
      <td>{{ inc.titulo }}</td>
      <td><img src="/icone.png" alt="{{ inc.ativo }}"></td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

TEMPLATE_INSEGURO = """
<!doctype html>
<html>
<head><title>Dashboard (INSEGURO - apenas para comparação)</title></head>
<body>
  <h1 style="color:red">⚠️ Versão INSEGURA — NÃO usar em produção</h1>
  <table border="1">
    <tr><th>Título</th><th>Ícone do ativo</th></tr>
    {% for inc in incidentes %}
    <tr>
      <td>{{ inc.titulo|safe }}</td>
      <td><img src="/icone.png" alt="{{ inc.ativo|safe }}"></td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""


@app.after_request
def aplicar_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.route("/dashboard")
def dashboard_seguro():
    db = conectar_mongo()
    incidentes = list(db.incidentes_dashboard.find({}, {"_id": 0}))
    return render_template_string(TEMPLATE_SEGURO, incidentes=incidentes)


@app.route("/dashboard-inseguro")
def dashboard_inseguro():
    """
    Rota claramente marcada como insegura, mantida apenas para
    comparação lado a lado. NUNCA fazer isso em produção: o uso de
    `|safe` sobre dado vindo do usuário reabre o XSS que a versão
    /dashboard evita.
    """
    db = conectar_mongo()
    incidentes = list(db.incidentes_dashboard.find({}, {"_id": 0}))
    return render_template_string(TEMPLATE_INSEGURO, incidentes=incidentes)


if __name__ == "__main__":
    popular_incidentes()
    app.run(debug=True, host="0.0.0.0")
