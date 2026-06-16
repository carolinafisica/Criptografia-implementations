from math import gcd


def a_order(a: int, n: int) -> int:
    r = 1
    val = a % n
    while val != 1:
        val = (val * a) % n
        r += 1
    return r


def factAux(a: int, n: int) -> tuple:

    # Passo 1: verificar gcd(a, n)
    g = gcd(a, n)
    if g != 1:
        return (g, "LuckyGuess")

    # Passo 2: calcular a ordem de a mod n, isso é o período da função
    r = a_order(a, n)

    # Passo 3: se r for impar, nao e possivel calcular a^(r/2)
    if r % 2 != 0:
        return (r, "OddOrder")

    # Passo 4: calcular x = gcd(a^(r/2) - 1, n)
    half_pow = pow(a, r // 2, n)   # a^(r/2) mod n, calculado eficientemente
    x = gcd(half_pow - 1, n)

    if x != 1:
        # x é um factor nao trivial de n; o outro é n // x
        return (x, "Factor")
    else:
        # gcd é 1, o que implica gcd(a^(r/2)+1, n) = n e isso não é útil
        return (r, "Trivial")


# =============================================================================
# TRÊS TESTES
# =============================================================================

if __name__ == '__main__':

    print("=" * 55)
    print("Testes com n = 15 (= 3 x 5)")
    print("=" * 55)
    n = 15
    for a in range(2, n):
        resultado, tipo = factAux(a, n)
        if tipo == "Factor":
            outro = n // resultado
            print(f"  a={a:2d} -> {tipo}: {resultado} x {outro} = {n}")
        elif tipo == "LuckyGuess":
            print(f"  a={a:2d} -> {tipo}: gcd({a},{n}) = {resultado}")
        else:
            print(f"  a={a:2d} -> {tipo}: r = {resultado}")

    print()
    print("=" * 55)
    print("Testes com n = 21 (= 3 x 7)")
    print("=" * 55)
    n = 21
    for a in range(2, n):
        resultado, tipo = factAux(a, n)
        if tipo == "Factor":
            outro = n // resultado
            print(f"  a={a:2d} -> {tipo}: {resultado} x {outro} = {n}")
        elif tipo == "LuckyGuess":
            print(f"  a={a:2d} -> {tipo}: gcd({a},{n}) = {resultado}")
        else:
            print(f"  a={a:2d} -> {tipo}: r = {resultado}")

    print()
    print("=" * 55)
    print("Testes com n = 35 (= 5 x 7)")
    print("=" * 55)
    n = 35
    for a in range(2, n):
        resultado, tipo = factAux(a, n)
        if tipo == "Factor":
            outro = n // resultado
            print(f"  a={a:2d} -> {tipo}: {resultado} x {outro} = {n}")
        elif tipo == "LuckyGuess":
            print(f"  a={a:2d} -> {tipo}: gcd({a},{n}) = {resultado}")
        else:
            print(f"  a={a:2d} -> {tipo}: r = {resultado}")



#==================================================================================================================
# TAREFA 2
#==================================================================================================================

def shor_stats(n: int) -> dict:
    counts = {"LuckyGuess": 0, "Factor": 0, "OddOrder": 0, "Trivial": 0}
    total = n - 2 

    for a in range(2, n):
        _, tipo = factAux(a, n)
        counts[tipo] += 1

    percentages = {k: 100.0 * v / total for k, v in counts.items()}
    success = percentages["Factor"] + percentages["LuckyGuess"]

    return {
        "n": n,
        "total_a": total,
        "counts": counts,
        "percentages": percentages,
        "success_rate": success,
    }


def print_stats(stats: dict, p: int, q: int) -> None:
    n = stats["n"]
    print(f"n = {n} = {p} x {q}   (total de valores de a testados: {stats['total_a']})")
    print(f"  {'Categoria':<14} {'Contagem':>8}  {'Percentagem':>12}")
    print(f"  {'-'*38}")
    for cat in ["Factor", "LuckyGuess", "OddOrder", "Trivial"]:
        c = stats["counts"][cat]
        p_ = stats["percentages"][cat]
        print(f"  {cat:<14} {c:>8}   {p_:>10.1f}%")
    print(f"  {'='*38}")
    print(f"  Probabilidade de sucesso (Factor + LuckyGuess): {stats['success_rate']:.1f}%")
    print()


# =============================================================================
# TESTES
# =============================================================================

if __name__ == '__main__':

    # Varios pares de primos para testar
    test_cases = [
        (3,  5),    # n = 15
        (3,  7),    # n = 21
        (5,  7),    # n = 35
        (7,  11),   # n = 77
        (11, 13),   # n = 143
        (17, 19),   # n = 323
        (23, 29),   # n = 667
        (31, 37),   # n = 1147
        (41, 43),   # n = 1763
        (53, 59),   # n = 3127
    ]

    print("=" * 55)
    print("ESTATISTICAS DO ALGORITMO DE FACTORIZACAO")
    print("=" * 55)
    print()

    success_rates = []

    for p, q in test_cases:
        n = p * q
        stats = shor_stats(n)
        print_stats(stats, p, q)
        success_rates.append(stats["success_rate"])

    # Media das taxas de sucesso
    media = sum(success_rates) / len(success_rates)
    print("=" * 55)
    print(f"Media das probabilidades de sucesso: {media:.1f}%")
  
