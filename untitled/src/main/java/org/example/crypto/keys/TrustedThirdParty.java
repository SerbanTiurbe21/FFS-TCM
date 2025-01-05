package org.example.crypto.keys;

import org.example.protocol.Prover;
import org.example.protocol.Verifier;

import java.math.BigInteger;

public class TrustedThirdParty {
    private final BigInteger n;
    private final BigInteger[] s; // Secret keys
    private final BigInteger[] v; // Public keys

    public TrustedThirdParty(final int bitLength, final int k) {
        final KeyGenerator keyGen = new KeyGenerator(bitLength, k);
        keyGen.generateKeys();
        n = keyGen.getN();
        s = keyGen.getSecretKeys();
        v = keyGen.getPublicKeys();
    }

    public void sendKeys(final Prover prover, final Verifier verifier) {
        prover.setN(n);
        prover.setS(s);
        verifier.setN(n);
        verifier.setV(v);
    }
}
