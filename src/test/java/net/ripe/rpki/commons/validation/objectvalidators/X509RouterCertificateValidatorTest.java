package net.ripe.rpki.commons.validation.objectvalidators;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509RouterCertificateTest;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;

import static org.junit.Assert.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class X509RouterCertificateValidatorTest {

    @Test
    public void shouldValidateRouterCertificateWithDefaultRootPredicate() {
        X509RouterCertificate child = createChildCertificate();
        X509RouterCertificate parent = createValidationParent(child.getIssuer(), child.getAuthorityKeyIdentifier());
        X509Crl crl = X509CrlTest.createCrl();
        ValidationResult result = ValidationResult.withLocation("router.cer");

        X509RouterCertificateValidator subject = new X509RouterCertificateValidator(ValidationOptions.strictValidation(), result, parent, crl);
        subject.validate("router.cer", child);

        assertFalse(result.hasFailures());
        assertFalse(result.hasWarnings());
    }

    @Test
    public void shouldValidateRouterCertificateWithoutCrlWhenPredicateTreatsItAsRoot() {
        X509RouterCertificate child = createChildCertificate();
        X509RouterCertificate parent = createValidationParent(child.getIssuer(), child.getAuthorityKeyIdentifier());
        ValidationResult result = ValidationResult.withLocation("router.cer");

        X509RouterCertificateValidator subject = new X509RouterCertificateValidator(ValidationOptions.strictValidation(), result, parent, null, certificate -> true);
        subject.validate("router.cer", child);

        assertFalse(result.hasFailures());
        assertFalse(result.hasWarnings());
    }

    private static X509RouterCertificate createChildCertificate() {
        return X509RouterCertificateTest.createSelfSignedRouterCertificateBuilder()
                .withSubjectDN(new X500Principal("CN=router-child"))
                .withIssuerDN(new X500Principal("CN=router-parent"))
                .withSerial(BigInteger.valueOf(901))
                .withKeyUsage(KeyUsage.digitalSignature)
                .build();
    }

    private static X509RouterCertificate createValidationParent(X500Principal subject, byte[] subjectKeyIdentifier) {
        X509RouterCertificate parent = mock(X509RouterCertificate.class);
        when(parent.isCa()).thenReturn(true);
        when(parent.getPublicKey()).thenReturn(KeyPairFactoryTest.TEST_KEY_PAIR.getPublic());
        when(parent.getSubject()).thenReturn(subject);
        when(parent.getSubjectKeyIdentifier()).thenReturn(subjectKeyIdentifier);
        when(parent.getResources()).thenReturn(IpResourceSet.parse("AS1"));
        return parent;
    }
}
