# ECC and RSA blind signature implementation
# used for performance comparison in research
import secrets
import hashlib
import time
import statistics
import math

from ecpy.curves import Curve
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


# ECC (Jeng scheme - Adapted)


class JengServer:
    def __init__(self, curve_name):
        self.curve = Curve.get_curve(curve_name)
        self.n = self.curve.order
        self.G = self.curve.generator

        self.n_s = secrets.randbelow(self.n - 1) + 1
        self.P_s = self.n_s * self.G

    def get_public_key(self):
        return self.P_s, self.curve.name

    def issue_blind_signature(self, alpha):
        # phase 2: Signing
        n_u = secrets.randbelow(self.n - 1) + 1
        r = n_u * alpha
        s = ((n_u + self.n_s) % self.n) * alpha
        return r, s


class JengClient:
    def __init__(self, server_P_s, curve_name):
        self.curve = Curve.get_curve(curve_name)
        self.n = self.curve.order
        self.G = self.curve.generator
        self.P_s = server_P_s

        self.n_i = secrets.randbelow(self.n - 1) + 1

    def prepare_blinded_message(self, msg):
        # phase 1: Blinding
        # hashing the message (using sha256)
        h = hashlib.sha256(msg).digest()
        m = int.from_bytes(h, 'big') % self.n

        scalar_alpha = (m * self.n_i * self.n_i) % self.n
        alpha = scalar_alpha * self.G
        return alpha, m

    def unblind_signature(self, r, s, m):
        # phase 3: Unblinding
        sub_scalar = (-(m * self.n_i)) % self.n
        s_prime = s + (sub_scalar * self.P_s)
        m_prime = (self.n_i * (self.n_i - 1) * m) % self.n
        return m_prime, s_prime, r

    def verify(self, m_prime, s_prime, r):
        return (s_prime + ((-m_prime) % self.n) * self.P_s) == r


def run_ecc_benchmark():
    curves = ['secp256r1', 'secp384r1', 'secp521r1']
    iterations = 100
    msg = b"Scientific Research Data: Vote 2026"

    print("\n=== ECC (Jeng) Benchmark ===")
    print(f"[{'Curve':<8}] | {'Blinding (ms)':<20} | {'Signing (ms)':<20} | {'Unblinding (ms)':<20}")
    print("-" * 75)

    for curve_name in curves:
        server = JengServer(curve_name)
        pub_key, curve = server.get_public_key()
        client = JengClient(pub_key, curve)

        t_blind, t_sign, t_unblind = [], [], []

        for _ in range(iterations):
            # Blinding
            start = time.perf_counter()
            alpha, m = client.prepare_blinded_message(msg)
            t_blind.append(time.perf_counter() - start)

            # Signing
            start = time.perf_counter()
            r, s = server.issue_blind_signature(alpha)
            t_sign.append(time.perf_counter() - start)

            # Unblinding
            start = time.perf_counter()
            m_prime, s_prime, r_final = client.unblind_signature(r, s, m)
            t_unblind.append(time.perf_counter() - start)

            assert client.verify(m_prime, s_prime, r_final)

        avg_b = statistics.mean(t_blind) * 1000
        std_b = statistics.stdev(t_blind) * 1000

        avg_s = statistics.mean(t_sign) * 1000
        std_s = statistics.stdev(t_sign) * 1000

        avg_u = statistics.mean(t_unblind) * 1000
        std_u = statistics.stdev(t_unblind) * 1000

        name = curve_name.replace('secp', 'P-').replace('r1', '')
        print(f"[{name:<8}] | {avg_b:.2f} ± {std_b:.2f} | {avg_s:.2f} ± {std_s:.2f} | {avg_u:.2f} ± {std_u:.2f}")


# RSA blind signature

def run_rsa_benchmark():
    # reducing iterations for 15360 because it takes way too long to compute
    test_cases = [
        {"keysize": 3072, "iterations": 50},
        {"keysize": 7680, "iterations": 10},
        {"keysize": 15360, "iterations": 2}
    ]

    msg = b"Scientific Research Data: Vote 2026"
    m = int.from_bytes(msg, 'big')

    print("\n=== RSA Benchmark ===")
    print(f"[{'Algorithm':<10}] | {'Blinding (ms)':<20} | {'Signing (ms)':<20} | {'Unblinding (ms)':<20}")
    print("-" * 75)

    for case in test_cases:
        keysize = case["keysize"]
        iterations = case["iterations"]
        # generating keys (this takes some time)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=keysize,
            backend=default_backend()
        )

        numbers = private_key.private_numbers()
        n = numbers.public_numbers.n
        e = numbers.public_numbers.e
        d = numbers.d

        t_blind, t_sign, t_unblind = [], [], []

        for _ in range(iterations):
            # phase 1: Blinding
            start = time.perf_counter()
            while True:
                r = secrets.randbelow(n - 1) + 1
                if math.gcd(r, n) == 1:
                    break
            m_prime = (m * pow(r, e, n)) % n
            t_blind.append(time.perf_counter() - start)

            # phase 2: Signing
            start = time.perf_counter()
            s_prime = pow(m_prime, d, n)
            t_sign.append(time.perf_counter() - start)

            # phase 3: Unblinding
            start = time.perf_counter()
            s = (s_prime * pow(r, -1, n)) % n
            t_unblind.append(time.perf_counter() - start)

            assert pow(s, e, n) == m
        # check for zero if iterations are too low
        avg_b = statistics.mean(t_blind) * 1000
        std_b = statistics.stdev(t_blind) * 1000 if len(t_blind) > 1 else 0

        avg_s = statistics.mean(t_sign) * 1000
        std_s = statistics.stdev(t_sign) * 1000 if len(t_sign) > 1 else 0

        avg_u = statistics.mean(t_unblind) * 1000
        std_u = statistics.stdev(t_unblind) * 1000 if len(t_unblind) > 1 else 0

        print(f"[RSA-{keysize:<5}] | {avg_b:.2f} ± {std_b:.2f} | {avg_s:.2f} ± {std_s:.2f} | {avg_u:.2f} ± {std_u:.2f}")


# main


if __name__ == "__main__":
    run_ecc_benchmark()
    run_rsa_benchmark()