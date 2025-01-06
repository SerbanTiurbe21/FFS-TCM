package main;

import org.example.crypto.keys.TrustedThirdParty;
import org.example.protocol.Prover;
import org.example.protocol.Verifier;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

class FeigeFiatShamirProtocolTest {
    private static final Logger logger = LoggerFactory.getLogger(FeigeFiatShamirProtocolTest.class);

    @Test
    void testRunProtocolWith1000() {
        runProtocolTest(1000);
    }

    @Test
    void testRunProtocolWith100() {
        runProtocolTest(100);
    }

    @Test
    void testRunProtocolWith10() {
        runProtocolTest(10);
    }

    private void runProtocolTest(int numberOfIterations) {
        final int bitLength = 512;
        final int k = 5;
        final boolean result = runProtocol(bitLength, k, numberOfIterations);

        if (result) {
            logger.info("Final Verification: Convinced after {} iterations", numberOfIterations);
        } else {
            logger.info("Final Verification: Not convinced");
        }
    }

    private boolean runProtocol(final int bitLength, final int k, final int numberOfIterations) {
        boolean result = true; // To store the final result of the verification

        long totalStartTime = System.nanoTime();
        // Initialize the trusted third party who generates and distributes the keys
        final TrustedThirdParty ttp = new TrustedThirdParty(bitLength, k);
        final Prover prover = new Prover();
        final Verifier verifier = new Verifier();
        ttp.sendKeys(prover, verifier); // TTP generates keys and sends them to both the prover and verifier

        long keySetupTime = System.nanoTime();
        logger.info("Key setup time: {} ns", (keySetupTime - totalStartTime));

        final SecureRandom rand = new SecureRandom(); // Initialize SecureRandom for generating random values for r

        long totalProtocolTime = 0;
        for (int i = 0; i < numberOfIterations; i++) {
            long roundStartTime = System.nanoTime();
            logger.info("---ROUND---: {}", i);

            final BigInteger r = generateRandomValue(bitLength, rand);
            final BigInteger x = prover.generateCommitment(r);
            final byte[] c = generateRandomChallenge(k, rand);
            final BigInteger y = prover.generateResponse(r, c, false);
            result = verifier.verify(x, y, c);

            long roundEndTime = System.nanoTime();
            totalProtocolTime += (roundEndTime - roundStartTime);
            logger.info("Round {} time: {} ns", i, (roundEndTime - roundStartTime));
            logger.info("Verification result: {}", result ? "Convinced" : "Not convinced");

            if (!result) {
                break; // If any verification fails, stop the testing
            }
        }

        long totalEndTime = System.nanoTime();
        logger.info("Total protocol execution time: {} ns", (totalEndTime - totalStartTime));
        logger.info("Average time per round: {} ns", totalProtocolTime / numberOfIterations);

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
