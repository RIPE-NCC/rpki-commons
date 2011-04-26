package net.ripe.commons.certification.cms.manifest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.net.URI;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.RpkiSignedObjectEeCertificateBuilder;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

public class RpkiSignedObjectEeCertificateBuilderTest {
    
    public static final int KEY_SIZE = 2048;
    public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String DEFAULT_SIGNATURE_PROVIDER = "SunRsaSign";
    
    private RpkiSignedObjectEeCertificateBuilder subject;

    @Before
    public void setUp() {
        subject = new RpkiSignedObjectEeCertificateBuilder();
    }

    @Test
    public void shouldCreateEeCertificate() {
        // given
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        
        URI crlUri = URI.create("rsync://somewhere/certificate.crl");
        subject.withCrlPublicationUri(crlUri);

        URI manifestUri = URI.create("rsync://somewhere/certificate.mft");
        subject.withCorrespondingCmsPublicationPoint(manifestUri);

        subject.withParentKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        subject.withEeKeyPair(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR);
        
        subject.withParentResourceCertificate(resourceCertificate);
        
        DateTime now = new DateTime();
        ValidityPeriod vp = new ValidityPeriod(now, now.plusSeconds(5));
        
        subject.withValidityPeriod(vp);

        URI publicationUri = URI.create("rsync://somewhere/certificate.cer");
        subject.withResourceCertificatePublicationUri(publicationUri);
        subject.withSerialNumber(BigInteger.TEN);
        
        subject.withSubject(new X500Principal("CN=subject"));
        
        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        subject.withSignatureAlgorithm(DEFAULT_SIGNATURE_ALGORITHM);

        // when
        X509ResourceCertificate certificate = subject.build();

        // then
        assertEquals(BigInteger.TEN, certificate.getSerialNumber());
        assertEquals(resourceCertificate.getSubject(), certificate.getIssuer());
        assertEquals(crlUri, certificate.getCrlUri());
        assertEquals(manifestUri, certificate.getSubjectInformationAccess()[0].getLocation());
        assertEquals(publicationUri, certificate.getAuthorityInformationAccess()[0].getLocation());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutSerialNumber() {
        // given
        createValidEeBuilder();
        subject.withSerialNumber(null);

        // when
        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutResourceCertificatePublicationUri() {
        // given
        createValidEeBuilder();
        subject.withResourceCertificatePublicationUri(null);

        // when
        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutValidityPeriod() {
        // given
        createValidEeBuilder();
        subject.withValidityPeriod(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutParentResourceCertificate() {
        // given
        createValidEeBuilder();
        subject.withParentResourceCertificate(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutParentKeyPair() {
        // given
        createValidEeBuilder();
        subject.withParentKeyPair(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutManifestUri() {
        // given
        createValidEeBuilder();
        subject.withCorrespondingCmsPublicationPoint(null);

        buildOrFail();
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotBuildWithoutCrlPublicationUri() {
        // given
        createValidEeBuilder();
        subject.withCrlPublicationUri(null);

        buildOrFail();
    }

    private void buildOrFail() {
        // when
        subject.build();

        // then
        fail("Should have thrown");
    }

    private void createValidEeBuilder() {
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
        URI crlUri = URI.create("rsync://somewhere/certificate.crl");
        subject.withCrlPublicationUri(crlUri);

        URI manifestUri = URI.create("rsync://somewhere/certificate.mft");
        subject.withCorrespondingCmsPublicationPoint(manifestUri);

        subject.withParentKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        subject.withParentResourceCertificate(resourceCertificate);
        
        DateTime now = new DateTime();
        subject.withValidityPeriod(new ValidityPeriod(now, now.plusSeconds(5)));

        URI publicationUri = URI.create("rsync://somewhere/certificate.cer");
        subject.withResourceCertificatePublicationUri(publicationUri);

        subject.withSerialNumber(BigInteger.TEN);
    }

}
