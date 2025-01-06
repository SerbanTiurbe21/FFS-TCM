package algos;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

class DSATest {
    @Test
    void testDSA1000() throws Exception {
        runDSATest(1000);
    }

    @Test
    void testDSA100() throws Exception {
        runDSATest(100);
    }

    @Test
    void testDSA10() throws Exception {
        runDSATest(10);
    }

    private void runDSATest(final int iterations) throws Exception {
        final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
        keyGen.initialize(2048); // 2048 bits is generally sufficient for DSA

        // Key generation timing
        long startTime = System.nanoTime();
        final KeyPair keyPair = keyGen.generateKeyPair();
        long endTime = System.nanoTime();
        System.out.println("DSA Key Generation Time: " + (endTime - startTime) + " ns");

        // Signing setup
        final Signature signature = Signature.getInstance("SHA256withDSA");
        signature.initSign(keyPair.getPrivate());
        final String message = "Test message";
        final byte[] messageBytes = message.getBytes();

        // Signing process
        byte[] digitalSignature = null;  // Declare outside to use it later in verification
        startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            signature.update(messageBytes); // Prepare the message for signing
            digitalSignature = signature.sign(); // Sign the data
        }
        endTime = System.nanoTime();
        System.out.println("Average DSA Signing Time: " + ((endTime - startTime) / iterations) + " ns");

        // Verification setup
        signature.initVerify(keyPair.getPublic());

        // Verification process
        startTime = System.nanoTime();
        boolean verified;
        for (int i = 0; i < iterations; i++) {
            signature.update(messageBytes); // Prepare the message for verification
            verified = signature.verify(digitalSignature); // Verify the digital signature
            System.out.println("Verified: " + verified);
        }
        endTime = System.nanoTime();
        System.out.println("Average DSA Verification Time: " + ((endTime - startTime) / iterations) + " ns");
    }
}
