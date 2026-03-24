#!/usr/bin/env python3
"""Compare certlint's digests against openssl dgst.

Lengths either side of both block boundaries, because the padding is the
part of a hand-written digest that goes wrong: 55, 56 and 57 for the
64-byte block, 111, 112 and 113 for the 128-byte one, zero, and a few
longer ones that need several blocks.
"""
import os
import subprocess
import sys

LENGTHS = ([0, 1, 2, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129,
            191, 192, 255, 256, 1000, 4096]
           + list(range(110, 118)))


def main(argv):
    binary, work = argv[1], argv[2]
    bad = 0
    n = 0
    for length in sorted(set(LENGTHS)):
        path = os.path.join(work, "h%d.bin" % length)
        # A deterministic filling, so a failure can be reproduced.
        with open(path, "wb") as f:
            f.write(bytes((i * 7 + 13) & 0xFF for i in range(length)))
        ours = {}
        out = subprocess.run([binary, "--hash", path], capture_output=True,
                             text=True, check=True).stdout
        for line in out.split("\n"):
            if line.strip():
                a, v = line.split()
                ours[a] = v
        for alg in ("sha1", "sha256", "sha384", "sha512"):
            r = subprocess.run(["openssl", "dgst", "-" + alg, path],
                               capture_output=True, text=True, check=True)
            want = r.stdout.strip().split("= ")[-1]
            n += 1
            if ours.get(alg) != want:
                bad += 1
                print("    length %d %s: ours %s, openssl %s"
                      % (length, alg, ours.get(alg), want))
        os.unlink(path)
    print("    %d digests over %d lengths, %d disagreed"
          % (n, len(set(LENGTHS)), bad))
    return min(bad, 125)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
