package org.example.protocol;

import lombok.RequiredArgsConstructor;

import java.math.BigInteger;

@RequiredArgsConstructor
public class Prover {
    private final BigInteger n;
    private final BigInteger[] s;

    public BigInteger generateCommitment(final BigInteger r) {
        return r.modPow(BigInteger.TWO, n);
    }

    public BigInteger generateResponse(final BigInteger r, final byte[] c) {
        BigInteger y = r;
        for (int i = 0; i < s.length; i++) {
            if (c[i] == 1) {
                y = y.multiply(s[i]).mod(n);
            }
        }
        return y;
    }
}
