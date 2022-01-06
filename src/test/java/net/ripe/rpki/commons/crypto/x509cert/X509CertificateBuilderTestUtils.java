package net.ripe.rpki.commons.crypto.x509cert;

import org.apache.commons.lang3.reflect.FieldUtils;
import org.bouncycastle.asn1.x509.PolicyInformation;

public class X509CertificateBuilderTestUtils {
    /**
     * Reflectively set policies to create non-compliant objects.
     */
    public static void setPoliciesOnBuilderHelperAttribute(Object builder, PolicyInformation... policies) {
        try {
            X509CertificateBuilderHelper builderHelper = (X509CertificateBuilderHelper) FieldUtils.readField(builder, "builderHelper", true);
            FieldUtils.writeField(builderHelper, "policies", policies, true);
            FieldUtils.writeField(builder, "builderHelper", builderHelper, true);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
