package org.example.protocol;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigInteger;

@Getter
@Setter
@NoArgsConstructor
public class Verifier {
    private BigInteger n;
    private BigInteger[] v;

    public boolean verify(final BigInteger x, final BigInteger y, final byte[] c) {
        final BigInteger left = y.modPow(BigInteger.TWO, n);
        BigInteger right = x;

        for (int i = 0; i < v.length; i++) {
            if (c[i] == 1) {
                right = right.multiply(v[i]).mod(n);
            }
        }
        return left.equals(right);
    }
}
