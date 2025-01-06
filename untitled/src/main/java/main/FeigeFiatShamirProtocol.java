package main;

import org.example.crypto.keys.TrustedThirdParty;
import org.example.protocol.Prover;
import org.example.protocol.Verifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

public class FeigeFiatShamirProtocol {
    private static final Logger logger = LoggerFactory.getLogger(FeigeFiatShamirProtocol.class);

    public static void main(String[] args) {
        final int bitLength = 512; // Defines the bit length for key generation
        final int k = 5; // Defines the number of iterations or the size of the arrays s and v
        final int numberOfIterations = 1000; // Number of times the protocol will run to verify consistency

        final FeigeFiatShamirProtocol protocol = new FeigeFiatShamirProtocol();
        boolean result = protocol.runProtocol(bitLength, k, numberOfIterations);

        if (result) {
            logger.info("Final Verification: Convinced after {} iterations", numberOfIterations);
        } else {
            logger.info("Final Verification: Not convinced");
        }
    }

    public boolean runProtocol(final int bitLength, final int k, final int numberOfIterations) {
        boolean result = true; // To store the final result of the verification
        // Initialize the trusted third party who generates and distributes the keys
        final TrustedThirdParty ttp = new TrustedThirdParty(bitLength, k);
        final Prover prover = new Prover();
        final Verifier verifier = new Verifier();
        ttp.sendKeys(prover, verifier); // TTP generates keys and sends them to both the prover and verifier
        final SecureRandom rand = new SecureRandom(); // Initialize SecureRandom for generating random values for r

        for (int i = 0; i < numberOfIterations; i++) {
            logger.info("---ROUND---: {}", i);

            final BigInteger r = generateRandomValue(bitLength, rand); // Generate a random r
            final BigInteger x = prover.generateCommitment(r); // Prover generates commitment x using r
            final byte[] c = generateRandomChallenge(k, rand); // Verifier generates a random challenge c
            final BigInteger y = prover.generateResponse(r, c, false); // Prover generates response y based on r and c
            result = verifier.verify(x, y, c); // Verifier verifies the proof
            logger.info("Verification result: {}", result ? "Convinced" : "Not convinced");
            if (!result) {
                break; // If any verification fails, stop the testing
            }
        }
        return result;
    }

    private BigInteger generateRandomValue(final int bitLength, final SecureRandom rand) {
        return new BigInteger(bitLength, rand);
    }

    private byte[] generateRandomChallenge(final int k, final SecureRandom rand) {
        byte[] c = new byte[k];
        rand.nextBytes(c);
        for (int j = 0; j < c.length; j++) {
            c[j] = (byte) (c[j] % 2); // Ensure that the challenge bits are only 0 or 1
        }
        return c;
    }
}