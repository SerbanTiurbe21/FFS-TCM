package org.example.protocol;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigInteger;

@Getter
@Setter
@NoArgsConstructor
public class Prover {
    private BigInteger n;
    private BigInteger[] s;

    public BigInteger generateCommitment(final BigInteger r) {
        return r.modPow(BigInteger.TWO, n);
    }

    public BigInteger generateResponse(final BigInteger r, final byte[] c, boolean simulateError) {
        BigInteger y = r;
        for (int i = 0; i < s.length; i++) {
            if (c[i] == 1) {
                y = y.multiply(s[i]).mod(n);
            }
        }
        if (simulateError) {
            y = y.add(BigInteger.ONE); // Deliberately offset the correct response
        }
        return y;
    }
}
