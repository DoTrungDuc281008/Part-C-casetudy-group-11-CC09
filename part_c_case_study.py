import numpy as np
import matplotlib.pyplot as plt

# ==========================================
# PART C1: CHEBYSHEV POLYNOMIALS & HILL CIPHER
# ==========================================
def chebyshev_matrix(n, x):
    """Compute Chebyshev polynomial T_n(x) via 2x2 matrix recursion."""
    if n == 0:
        return 1.0
    M = np.array([[2.0 * x, -1.0], [1.0, 0.0]], dtype=np.float64)
    vec = np.linalg.matrix_power(M, n - 1) @ np.array([x, 1.0], dtype=np.float64)
    return float(vec[0])

def chebyshev_trig(n, x):
    """Compute Chebyshev polynomial T_n(x) via cos(n * arccos(x))."""
    return float(np.cos(n * np.arccos(x)))

def run_c1():
    print("--- C1: FLOATING-POINT COMPARISON ---")
    x = 0.654321
    r, s = 17, 23
    rs = r * s

    for label, deg in [("T_s(x)", s), ("T_r(x)", r), ("T_rs(x)", rs)]:
        val_mat = chebyshev_matrix(deg, x)
        val_trig = chebyshev_trig(deg, x)
        diff = abs(val_mat - val_trig)
        print(f"{label:8s} (n={deg:3d}): Matrix = {val_mat:+.15f} | Trig = {val_trig:+.15f} | Diff = {diff:.2e}")

    # Verify semigroup commutativity: T_r(T_s(x)) == T_s(T_r(x))
    t_r_s = chebyshev_matrix(r, chebyshev_matrix(s, x))
    t_s_r = chebyshev_matrix(s, chebyshev_matrix(r, x))
    print(f"Commutativity |T_r(T_s(x)) - T_s(T_r(x))| = {abs(t_r_s - t_s_r):.2e}\n")

    print("--- C1: HILL CIPHER DECRYPTION MOD 29 ---")
    # 29-character alphabet (A-Z = 0..25, ' ' = 26, '.' = 27, '?' = 28)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ .?"
    char_to_num = {c: i for i, c in enumerate(alphabet)}
    num_to_char = {i: c for i, c in enumerate(alphabet)}

    # Key matrix A (det(A) = -1 == 28 mod 29, invertible mod 29)
    A = np.array([[1, 2], [3, 5]], dtype=int)
    det = int(round(np.linalg.det(A))) % 29
    det_inv = pow(det, -1, 29)
    adj = np.array([[A[1, 1], -A[0, 1]], [-A[1, 0], A[0, 0]]], dtype=int)
    A_inv = (det_inv * adj) % 29

    ciphertext = "GERPLYNDBX"
    nums = [char_to_num[c] for c in ciphertext]
    plaintext = []
    for i in range(0, len(nums), 2):
        block = np.array(nums[i:i+2])
        dec_block = (A_inv @ block) % 29
        plaintext.extend([num_to_char[int(v)] for v in dec_block])

    print(f"Ciphertext : {ciphertext}")
    print(f"Key A^-1   :\n{A_inv}")
    print(f"Decrypted  : {''.join(plaintext)}\n")

# ==========================================
# PART C2: SIRI ATTACK & MODULAR CHEBYSHEV
# ==========================================
def siri_attack_real(x, A_pub, max_k=100):
    """Recover private key s from public x and A = T_s(x) over the reals."""
    acos_x = np.arccos(x)
    acos_A = np.arccos(A_pub)
    for k in range(max_k):
        s_cand = (acos_A + 2 * np.pi * k) / acos_x
        s_int = int(round(s_cand))
        if s_int > 0 and abs(chebyshev_trig(s_int, x) - A_pub) < 1e-9:
            return s_int
    return None

def chebyshev_mod_p(n, x, p):
    """Compute Chebyshev polynomial T_n(x) mod p using binary matrix exponentiation."""
    if n == 0:
        return 1 % p
    M = np.array([[2 * x % p, (-1) % p], [1, 0]], dtype=object)
    res = np.array([[1, 0], [0, 1]], dtype=object)
    power = n - 1
    while power > 0:
        if power % 2 == 1:
            res = (res @ M) % p
        M = (M @ M) % p
        power //= 2
    return int((res[0, 0] * x + res[0, 1]) % p)

def run_c2():
    print("--- C2: REAL-NUMBER KEY RECOVERY & MODULAR CHEBYSHEV ---")
    x_real = 0.42
    s_secret, r_secret = 37, 53
    A_pub = chebyshev_trig(s_secret, x_real)
    s_recovered = siri_attack_real(x_real, A_pub)
    print(f"[Real-number Attack] Secret s = {s_secret} -> Siri recovered s = {s_recovered}")

    # Modular Chebyshev key exchange over small primes p
    for p in [101, 1009, 10007]:
        x_mod = 19 % p
        A_mod = chebyshev_mod_p(s_secret, x_mod, p)
        B_mod = chebyshev_mod_p(r_secret, x_mod, p)
        K_alice = chebyshev_mod_p(s_secret, B_mod, p)
        K_bob = chebyshev_mod_p(r_secret, A_mod, p)
        assert K_alice == K_bob
        print(f"[Mod p = {p:5d}] A = {A_mod:4d}, B = {B_mod:4d} => Shared Key K = {K_alice:4d} (Match: True)")
    print()

# ==========================================
# PART C3: RUNGE PHENOMENON & CHEBYSHEV NODES
# ==========================================
def runge(x):
    return 1.0 / (1.0 + 25.0 * x**2)

def barycentric_interp(x_nodes, y_nodes, x_eval):
    """Numerically stable barycentric Lagrange interpolation."""
    n = len(x_nodes)
    w = np.ones(n)
    for j in range(n):
        for k in range(n):
            if j != k:
                w[j] /= (x_nodes[j] - x_nodes[k])

    y_eval = np.zeros_like(x_eval)
    for i, xv in enumerate(x_eval):
        diff = xv - x_nodes
        exact = np.where(np.abs(diff) < 1e-14)[0]
        if len(exact) > 0:
            y_eval[i] = y_nodes[exact[0]]
        else:
            terms = w / diff
            y_eval[i] = np.sum(terms * y_nodes) / np.sum(terms)
    return y_eval

def run_c3():
    print("--- C3: RUNGE FUNCTION INTERPOLATION MAX ERROR TABLE ---")
    x_fine = np.linspace(-1, 1, 2000)
    y_true = runge(x_fine)
    ns = [5, 10, 20]

    print(f"{'n':>4s} | {'Equally Spaced Max Error':>26s} | {'Chebyshev Max Error':>22s}")
    print("-" * 60)

    fig, axes = plt.subplots(1, 3, figsize=(15, 4.5), dpi=120)
    for idx, n in enumerate(ns):
        # Equally spaced nodes
        x_eq = np.linspace(-1, 1, n + 1)
        y_eq_interp = barycentric_interp(x_eq, runge(x_eq), x_fine)
        err_eq = np.max(np.abs(y_true - y_eq_interp))

        # Chebyshev nodes (first kind)
        j = np.arange(n + 1)
        x_ch = np.cos((2 * j + 1) * np.pi / (2 * (n + 1)))
        y_ch_interp = barycentric_interp(x_ch, runge(x_ch), x_fine)
        err_ch = np.max(np.abs(y_true - y_ch_interp))

        print(f"{n:4d} | {err_eq:26.6e} | {err_ch:22.6e}")

        # Plot comparison
        ax = axes[idx]
        ax.plot(x_fine, y_true, 'k-', lw=2, label='f(x) = 1/(1+25x^2)')
        ax.plot(x_fine, y_eq_interp, 'r--', lw=1.3, label='Equally spaced')
        ax.plot(x_fine, y_ch_interp, 'b-.', lw=1.5, label='Chebyshev nodes')
        ax.set_title(f"Degree n = {n}")
        ax.set_xlabel("x")
        ax.set_ylabel("y")
        ax.set_ylim(-0.5, 1.5)
        ax.grid(True, alpha=0.3)
        if idx == 0:
            ax.legend(loc='upper right', fontsize=8)

    plt.tight_layout()
    plt.savefig("c3_runge_comparison.png")
    plt.show()

if __name__ == "__main__":
    run_c1()
    run_c2()
    run_c3()