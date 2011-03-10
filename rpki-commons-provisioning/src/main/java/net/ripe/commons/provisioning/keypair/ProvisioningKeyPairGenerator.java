package net.ripe.commons.provisioning.keypair;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.RSAKeyGenParameterSpec;


/**
 * Only software keys (no HSM) are supported for the moment.
 * The provisioning draft refers to this section for the algorithm,
 * key size and public exponent:
 *
 * http://tools.ietf.org/html/draft-huston-sidr-rpki-algs-00#section-2
 */
public final class ProvisioningKeyPairGenerator {

    private static final String ALGORITHM = "RSA";
    private static final String KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    private static final int IDENTITY_KEY_SIZE = 2048;

    private ProvisioningKeyPairGenerator() {
        //Utility classes should not have a public or default constructor.
    }

    public static KeyPair generate() {
        try {
            KeyPairGenerator generator;
            generator = KeyPairGenerator.getInstance(ALGORITHM, KEYPAIR_GENERATOR_PROVIDER);
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
