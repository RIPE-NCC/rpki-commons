package net.ripe.commons.provisioning.keypair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.RSAKeyGenParameterSpec;


/**
 * Only software keys (no HSM) are supported for the moment. The provisioning draft is unclear about
 * key size requirements, but it seems a good idea to keep this similar to resource certificates:
 * 2048 bit keys and RSA
 */
public class ProvisioningKeyPairGenerator {

    private static final String ALGORITHM = "RSA";
    private static final String SUN_RSA_SIGN = "SunRsaSign";
    private static final int IDENTITY_KEY_SIZE = 2048;

    public static KeyPair generate() {
        try {
            KeyPairGenerator generator;
            generator = KeyPairGenerator.getInstance(ALGORITHM, SUN_RSA_SIGN);
            generator.initialize(new RSAKeyGenParameterSpec(IDENTITY_KEY_SIZE, RSAKeyGenParameterSpec.F4));
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new ProvisioningKeyPairGeneratorException(e);
        } catch (NoSuchProviderException e) {
            throw new ProvisioningKeyPairGeneratorException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new ProvisioningKeyPairGeneratorException(e);
        }
    }
}
