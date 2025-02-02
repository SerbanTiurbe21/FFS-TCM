package org.example.crypto.keys;

import lombok.Getter;

import java.math.BigInteger;
import java.security.SecureRandom;

public class KeyGenerator {
    @Getter
    private BigInteger n;
    private BigInteger[] s; // Secret keys
    private BigInteger[] v; // Public keys
    private final int k; // Security parameter
    private final int bitLength;

    public KeyGenerator(int bitLength, int k) {
        this.k = k;
        this.bitLength = bitLength;
    }

    // Make generateKeys public to allow external triggering
    public void generateKeys() {
        final PrimeGenerator pg = new PrimeGenerator(bitLength);
        final BigInteger p = pg.generatePrime();
        final BigInteger q = pg.generatePrime();
        n = p.multiply(q);

        final SecureRandom rand = new SecureRandom();
        s = new BigInteger[k];
        v = new BigInteger[k];
        for (int i = 0; i < k; i++) {
            s[i] = new BigInteger(bitLength, rand).mod(n);
            v[i] = s[i].modPow(BigInteger.TWO, n);
        }
    }

    public BigInteger[] getSecretKeys() {
        return s;
    }

    public BigInteger[] getPublicKeys() {
        return v;
    }
}
