#!/usr/bin/env python3
"""Compare certlint's modular exponentiation against python's pow().

python's integers are an independent arbitrary-precision implementation,
which is the only outside authority for this on the machine that does not
go through openssl. Sizes run from one limb to a real RSA modulus, and the
moduli are odd because Montgomery needs them to be.
"""
import random
import subprocess
import sys

SIZES = [1, 2, 3, 8, 16, 17, 31, 32, 33, 64, 128, 256]


def main(argv):
    binary = argv[1]
    seed = int(argv[2]) if len(argv) > 2 else 20261020
    rnd = random.Random(seed)
    bad = 0
    n = 0
    for size in SIZES:
        for _ in range(4):
            m = rnd.getrandbits(size * 8) | 1 | (1 << (size * 8 - 1))
            b = rnd.getrandbits(size * 8)
            e = rnd.getrandbits(min(size, 8) * 8)
            want = pow(b, e, m)
            out = subprocess.run(
                [binary, "--modexp", "%x" % b, "%x" % e, "%x" % m],
                capture_output=True, text=True, check=True).stdout.strip()
            n += 1
            if int(out, 16) != want:
                bad += 1
                print("    %d-byte modulus: ours %s, python %x" % (size, out, want))
    # The edges, where an off-by-one in the exponent loop lives.
    for b, e, m in ((0, 65537, 0xF7), (1, 0, 0xF7), (0xF6, 1, 0xF7),
                    (0xF7, 1, 0xF7), (2, 1, 3)):
        want = pow(b, e, m)
        out = subprocess.run(
            [binary, "--modexp", "%x" % b, "%x" % e, "%x" % m],
            capture_output=True, text=True, check=True).stdout.strip()
        n += 1
        if int(out, 16) != want:
            bad += 1
            print("    edge %x^%x mod %x: ours %s, python %x" % (b, e, m, out, want))
    print("    %d exponentiations against python pow, %d disagreed" % (n, bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
