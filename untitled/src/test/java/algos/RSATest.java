package algos;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

class RSATest {
    @Test
    void testRSA1000() throws Exception {
        runRSATest(1000);
    }

    @Test
    void testRSA100() throws Exception {
        runRSATest(100);
    }

    @Test
    void testRSA10() throws Exception {
        runRSATest(10);
    }

    private void runRSATest(final int iterations) throws Exception {
        // Key Generation
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Standard secure key size

        long startTime = System.nanoTime();
        final KeyPair keyPair = keyGen.generateKeyPair();
        final long keyGenTime = System.nanoTime() - startTime;
        System.out.println("RSA Key Generation Time: " + keyGenTime + " ns");

        // Signing
        final Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        final String message = "Test message";
        final byte[] messageBytes = message.getBytes();

        startTime = System.nanoTime();
        signature.update(messageBytes);
        final byte[] digitalSignature = signature.sign(); // Generate digital signature once
        final long signingTime = System.nanoTime() - startTime;

        // Reset startTime for verification timing
        signature.initVerify(keyPair.getPublic());
        signature.update(messageBytes);

        startTime = System.nanoTime();
        boolean verified;
        for (int i = 0; i < iterations; i++) {
            verified = signature.verify(digitalSignature); // Use the same digital signature for verification
            System.out.println("Verified: " + verified);
        }
        final long verificationTime = System.nanoTime() - startTime;

        System.out.println("RSA Signing Time: " + signingTime + " ns");
        System.out.println("Average RSA Verification Time: " + (verificationTime / iterations) + " ns");
    }
}
