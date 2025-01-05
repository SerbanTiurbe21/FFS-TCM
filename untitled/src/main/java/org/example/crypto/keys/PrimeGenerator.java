package org.example.crypto.keys;

import lombok.RequiredArgsConstructor;

import java.math.BigInteger;
import java.security.SecureRandom;

@RequiredArgsConstructor
public class PrimeGenerator {
    private final int bitLength;

    public BigInteger generatePrime() {
        final SecureRandom rand = new SecureRandom();
        return BigInteger.probablePrime(bitLength / 2, rand);
    }
}
