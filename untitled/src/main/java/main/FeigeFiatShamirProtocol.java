package main;

import org.example.crypto.keys.KeyGenerator;
import org.example.protocol.Prover;
import org.example.protocol.Verifier;

import java.math.BigInteger;
import java.security.SecureRandom;

public class FeigeFiatShamirProtocol {
    public static void main(String[] args) {
        final int bitLength = 512;
        final int k = 5;
        final KeyGenerator keyGen = new KeyGenerator(bitLength, k);
        final BigInteger n = keyGen.getN();
        final BigInteger[] s = keyGen.getS(); // Secret keys
        final BigInteger[] v = keyGen.getV(); // Public keys

        final Prover prover = new Prover(n, s);
        final Verifier verifier = new Verifier(n, v);

        final SecureRandom rand = new SecureRandom();
        final BigInteger r = new BigInteger(bitLength, rand);
        final byte[] c = new byte[k]; // Example challenge
        rand.nextBytes(c); // Generating random challenge bits

        final BigInteger x = prover.generateCommitment(r);
        final BigInteger y = prover.generateResponse(r, c);

        System.out.println("Verification: " + verifier.verify(x, y, c));
    }
}
