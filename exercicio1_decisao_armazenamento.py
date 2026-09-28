"""
Exercício 1 — Assistente de decisão de armazenamento (Aulas 1 e 8)

A ideia central: cada característica do perfil de dados empurra a decisão
em uma direção. Em vez de um emaranhado de "if" soltos, cada regra vira
uma linha de uma tabela de decisão (lista de tuplas), e a função apenas
percorre essa tabela procurando a primeira regra cujo predicado bate com
o perfil. Isso deixa a lógica auditável: dá pra ler a tabela como uma
política de segurança, não como um fluxo de código disperso.
"""

from typing import Callable, NamedTuple


class Regra(NamedTuple):
    nome: str
    predicado: Callable[[dict], bool]
    banco: str
    cap: str
    justificativa: str
    risco_owasp: str


def _regras() -> list[Regra]:
    return [
        Regra(
            nome="dado_sensivel_com_acid_e_schema_fixo",
            predicado=lambda p: p["dado_sensivel"] and p["precisa_acid"] and p["schema_fixo"],
            banco="MySQL",
            cap="CP",
            justificativa=(
                "dado sensível com necessidade de ACID não pode aceitar leitura "
                "inconsistente: autenticar ou cobrar com base em um valor errado "
                "é pior do que recusar a operação e ficar temporariamente indisponível"
            ),
            risco_owasp="A07:2021 - Falhas de Identificação e Autenticação",
        ),
        Regra(
            nome="auditoria_sensivel_sem_acid",
            predicado=lambda p: p["dado_sensivel"] and not p["precisa_acid"] and not p["tolera_atraso_de_consistencia"],
            banco="MongoDB",
            cap="CP",
            justificativa=(
                "é uma trilha de evidências: um registro de auditoria que diverge "
                "entre réplicas não serve como prova, então vale mais recusar a "
                "escrita/leitura do que aceitar uma versão desatualizada"
            ),
            risco_owasp="A08:2021 - Falhas de Integridade de Software e Dados",
        ),
        Regra(
            nome="tolera_atraso_e_escala",
            predicado=lambda p: p["tolera_atraso_de_consistencia"] and p["escala_horizontal"] and not p["dado_sensivel"],
            banco="MongoDB",
            cap="AP",
            justificativa=(
                "é telemetria de alto volume: perder um segundo de consistência "
                "entre nós é aceitável, mas parar de aceitar escrita durante uma "
                "partição de rede faria o sistema perder dados de monitoramento "
                "justamente na hora em que mais precisa deles"
            ),
            risco_owasp="A09:2021 - Falhas de Log e Monitoramento de Segurança",
        ),
        Regra(
            nome="cache_sensivel_tolerante",
            predicado=lambda p: p["tolera_atraso_de_consistencia"] and p["dado_sensivel"] and p["schema_fixo"],
            banco="MongoDB",
            cap="AP",
            justificativa=(
                "é um cache de sessão: precisa responder rápido mesmo sob falha "
                "de rede, e uma sessão levemente desatualizada é tolerável — mas "
                "por guardar dado sensível, a expiração e a invalidação precisam "
                "ser tratadas com cuidado para não manter uma sessão revogada viva"
            ),
            risco_owasp="A07:2021 - Falhas de Identificação e Autenticação",
        ),
        Regra(
            nome="sensivel_com_escala_sem_acid",
            predicado=lambda p: p["dado_sensivel"] and p["escala_horizontal"] and not p["precisa_acid"],
            banco="MongoDB",
            cap="CP",
            justificativa=(
                "precisa crescer horizontalmente, mas por lidar com dado sensível "
                "não pode arriscar responder com uma cópia desatualizada durante "
                "uma partição — melhor recusar temporariamente do que vazar ou "
                "aplicar uma versão antiga de uma permissão, por exemplo"
            ),
            risco_owasp="A01:2021 - Falhas de Controle de Acesso",
        ),
        Regra(
            nome="schema_fixo_acid_sem_sensibilidade",
            predicado=lambda p: p["schema_fixo"] and p["precisa_acid"] and not p["dado_sensivel"],
            banco="MySQL",
            cap="CP",
            justificativa=(
                "é um domínio transacional clássico (ex.: carrinho/licenças): "
                "cobrar duas vezes ou liberar um item sem pagamento confirmado "
                "é um erro de negócio inaceitável, mesmo que não envolva dado "
                "sensível — vale mais recusar a operação do que aceitar uma "
                "transação parcialmente aplicada"
            ),
            risco_owasp="A04:2021 - Design Inseguro",
        ),
    ]


def recomendar(perfil: dict) -> dict:
    """
    Recebe o perfil de um conjunto de dados e devolve uma recomendação
    fundamentada de banco, lado do CAP a priorizar e risco OWASP associado
    a uma escolha errada.
    """
    chaves_esperadas = {
        "schema_fixo",
        "precisa_acid",
        "escala_horizontal",
        "tolera_atraso_de_consistencia",
        "dado_sensivel",
    }
    faltando = chaves_esperadas - perfil.keys()
    if faltando:
        raise ValueError(f"perfil incompleto, faltam as chaves: {faltando}")

    for regra in _regras():
        if regra.predicado(perfil):
            return {
                "banco": regra.banco,
                "cap": regra.cap,
                "justificativa": regra.justificativa,
                "risco_owasp": regra.risco_owasp,
            }

    # Regra padrão (fallback): nenhuma condição específica bateu.
    return {
        "banco": "MySQL",
        "cap": "CP",
        "justificativa": (
            "perfil sem sinais fortes de escala ou tolerância a atraso: na "
            "dúvida, prioriza-se consistência para evitar decisões tomadas "
            "sobre dado desatualizado"
        ),
        "risco_owasp": "A04:2021 - Design Inseguro",
    }


if __name__ == "__main__":
    perfis = {
        "credenciais_do_SOC": {
            "schema_fixo": True, "precisa_acid": True, "escala_horizontal": False,
            "tolera_atraso_de_consistencia": False, "dado_sensivel": True,
        },
        "telemetria_de_sensores": {
            "schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,
            "tolera_atraso_de_consistencia": True, "dado_sensivel": False,
        },
        "trilha_de_auditoria": {
            "schema_fixo": False, "precisa_acid": False, "escala_horizontal": True,
            "tolera_atraso_de_consistencia": False, "dado_sensivel": True,
        },
        "carrinho_de_licencas": {
            "schema_fixo": True, "precisa_acid": True, "escala_horizontal": False,
            "tolera_atraso_de_consistencia": False, "dado_sensivel": False,
        },
        "cache_de_sessoes": {
            "schema_fixo": True, "precisa_acid": False, "escala_horizontal": True,
            "tolera_atraso_de_consistencia": True, "dado_sensivel": True,
        },
    }

    for nome, perfil in perfis.items():
        r = recomendar(perfil)
        print(f"{nome:24s} -> {r['banco']:7s} | {r['cap']} | \"{r['justificativa'][:55]}...\" | {r['risco_owasp'].split(':')[0]}")
