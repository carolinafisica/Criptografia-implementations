from math import gcd


def f(x: int, alpha: int, beta: int, g: int, p: int) -> int:
    """
    Avalia a funcao f(alpha, beta) = (x^alpha * g^beta) mod p.
    Procura-se os pares (alpha, beta) onde f = 1.
    """
    return (pow(x, alpha, p) * pow(g, beta, p)) % p


def find_solutions(x: int, g: int, p: int, q: int) -> list:
    """
    Encontra por forca bruta todos os pares (alpha, beta) com
    alpha, beta em [0, q-1] tais que:

      (x^alpha * g^beta) mod p = 1

    Existem exatamente q pares que satisfazem esta equacao
    (um para cada valor de alpha, ha um unico beta que funciona).

    Retorna lista de (alpha, beta).
    """
    solutions = []
    for alpha in range(q):
        for beta in range(q):
            if f(x, alpha, beta, g, p) == 1:
                solutions.append((alpha, beta))
    return solutions


def discrete_log(x: int, g: int, p: int, q: int) -> int | None:
    """
    Calcula log_g(x) mod q a partir das solucoes.

    Para cada par (alpha, beta) solucao de f = 1:
      alpha * log_g(x) + beta ≡ 0 (mod q)
      log_g(x) = -beta * alpha^(-1) mod q   (se gcd(alpha, q) = 1)

    """
    solutions = find_solutions(x, g, p, q)

    for alpha, beta in solutions:
        if alpha == 0:
            continue  # alpha=0 nao permite isolar o logaritmo
        if gcd(alpha, q) == 1:
            # alpha tem inversa mod q logo pode se calcular o log
            alpha_inv = pow(alpha, -1, q)     # inversa de alpha mod q
            log = (-beta * alpha_inv) % q
            return log, (alpha, beta)         # devolve log e par usado

    return None  # nenhum par utilizavel (improvavel para q primo)


# =============================================================================
# TESTES
# =============================================================================

if __name__ == '__main__':

    print("=" * 55)
    print("LOGARITMO DISCRETO VIA PERIOD FINDING")
    print("=" * 55)

    # --- Exemplo 1: p=11, g=2 (ordem q=10) ---
    # Verificar: 2^k mod 11 para k=0..9
    p, g, q = 11, 2, 10

    print(f"\np={p}, g={g} (ordem q={q})")
    print(f"Tabela: g^k mod p para k=0..{q-1}:")
    for k in range(q):
        print(f"  g^{k} mod {p} = {pow(g, k, p)}")

    print()
    # Testar para varios valores de x
    for x in [3, 4, 5, 9]:
        result = discrete_log(x, g, p, q)
        if result is not None:
            log, (alpha, beta) = result
            # verificar
            check = pow(g, log, p)
            print(f"  log_{g}({x}) mod {p} = {log}   "
                  f"[via par (a={alpha}, b={beta})]   "
                  f"verificacao: {g}^{log} mod {p} = {check}")
        else:
            print(f"  log_{g}({x}): nao encontrado")

    # --- Mostrar TODAS as solucoes para x=3 ---
    x = 3
    sols = find_solutions(x, g, p, q)
    print(f"\nTodas as {len(sols)} solucoes para x={x}, g={g}, p={p}, q={q}:")
    print(f"  (alpha, beta) tais que (x^alpha * g^beta) mod p = 1")
    for alpha, beta in sols:
        val = f(x, alpha, beta, g, p)
        utilizavel = "gcd=1, utilizavel" if gcd(alpha, q) == 1 else f"gcd={gcd(alpha,q)}, nao utilizavel"
        if alpha == 0:
            utilizavel = "alpha=0, nao utilizavel"
        print(f"  (a={alpha:2d}, b={beta:2d})  f={val}  {utilizavel}")

    # --- Exemplo 2: p=23, g=5 (ordem q=22) ---
    print()
    print("=" * 55)
    p, g, q = 23, 5, 22
    print(f"p={p}, g={g} (ordem q={q})")
    for x in [2, 7, 10, 15]:
        result = discrete_log(x, g, p, q)
        if result is not None:
            log, (alpha, beta) = result
            check = pow(g, log, p)
            print(f"  log_{g}({x:2d}) mod {p} = {log:2d}   "
                  f"[par (a={alpha}, b={beta})]   "
                  f"verif: {g}^{log} mod {p} = {check}")

    # --- Exemplo 3 (Tarefa 4): g=2, p=37, q=36  (q composto) ---
    print()
    p, g, q = 37, 2, 36
    for x in [2, 3, 5, 10, 36]:
        result = discrete_log(x, g, p, q)
        if result is not None:
            log, (alpha, beta) = result
            check = pow(g, log, p)
            print(f"  log_{g}({x:2d}) mod {p} = {log:2d}   "
                  f"[par (a={alpha}, b={beta})]   "
                  f"verif: {g}^{log} mod {p} = {check}")
        else:
            print(f"  log_{g}({x}): nao encontrado")

    # --- Exemplo 4 (Tarefa 4): g=2, p=23, q=11  ---
    print()
    p, g, q = 23, 2, 11
    for x in [2, 3, 4, 6, 8]:
        result = discrete_log(x, g, p, q)
        if result is not None:
            log, (alpha, beta) = result
            check = pow(g, log, p)
            print(f"  log_{g}({x:2d}) mod {p} = {log:2d}   "
                  f"[par (a={alpha}, b={beta})]   "
                  f"verif: {g}^{log} mod {p} = {check}")
        else:
            print(f"  log_{g}({x}): nao encontrado")


def success_stats(x: int, g: int, p: int, q: int) -> dict:
    """
    Para um dado x, conta quantos dos q pares solucao sao utilizaveis.
    Um par (alpha, beta) e utilizavel se gcd(alpha, q) = 1 (com alpha != 0).
    """
    solutions = find_solutions(x, g, p, q)
    total   = len(solutions)   # deve ser sempre q
    usable  = 0
    skipped = 0

    for alpha, beta in solutions:
        if alpha == 0:
            skipped += 1   # alpha=0 nao permite isolar o log
        elif gcd(alpha, q) == 1:
            usable += 1
        # senao: gcd != 1, nao utilizavel

    unusable = total - usable - skipped

    return {
        "x": x, "total": total,
        "usable": usable, "unusable": unusable, "alpha0": skipped,
        "success_rate": 100.0 * usable / total,
    }


def phi(n: int) -> int:
    return sum(1 for k in range(1, n) if gcd(k, n) == 1)


def run_scenario(g: int, p: int, q: int, label: str) -> None:
    print(f"\n{'='*58}")
    print(f"CENARIO: {label}")
    print(f"  g={g}, p={p}, q={q}   [phi(q)={phi(q)}, phi(q)/q = {phi(q)/q:.3f}]")
    print(f"{'='*58}")

    # Testar todos os x possiveis no grupo gerado por g
    # (x = g^k mod p para k=1..q-1; ignoramos x=1 pq log=0 e trivial)
    elements = [pow(g, k, p) for k in range(1, q)]

    rates = []
    print(f"  {'x':>4}  {'usable':>7}  {'unusable':>9}  {'alpha=0':>7}  {'sucesso':>8}")
    print(f"  {'-'*46}")

    for x in elements:
        s = success_stats(x, g, p, q)
        rates.append(s["success_rate"])
        print(f"  {x:>4}  {s['usable']:>7}  {s['unusable']:>9}  "
              f"{s['alpha0']:>7}  {s['success_rate']:>7.1f}%")

    media = sum(rates) / len(rates)
    print(f"  {'-'*46}")
    print(f"  Media da taxa de sucesso: {media:.1f}%")
    print(f"  phi(q)/q (teorico):       {100*phi(q)/q:.1f}%")


# =============================================================================
# TESTES
# =============================================================================

if __name__ == '__main__':

    print("PROBABILIDADE DE SUCESSO DO ALGORITMO DE SHOR")
    print("para o calculo do Logaritmo Discreto")

    # Cenario 1: g=2, p=37, q=36  (q composto: 36 = 4*9)
    run_scenario(g=2, p=37, q=36, label="g=2, p=37, q=36  (q composto)")

    # Cenario 2: g=2, p=23, q=11  (Safe Prime: p = 2*11+1 = 23)
    run_scenario(g=2, p=23, q=11, label="g=2, p=23, q=11  (Safe Prime: p=2q+1, q primo)")

    
