package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.RpkiSignedObjectEeCertificateBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import org.junit.Before;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.time.Instant;
import java.util.EnumSet;

import static org.junit.Assert.*;

public class RpkiSignedObjectEeCertificateBuilderTest {

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
        subject.withCrlUri(crlUri);

        URI manifestUri = URI.create("rsync://somewhere/certificate.mft");
        subject.withCorrespondingCmsPublicationPoint(manifestUri);

        subject.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        subject.withPublicKey(KeyPairFactoryTest.SECOND_TEST_KEY_PAIR.getPublic());


        var now = Instant.now();
        ValidityPeriod vp = new ValidityPeriod(now, now.plusSeconds(5));

        subject.withValidityPeriod(vp);

        URI publicationUri = URI.create("rsync://somewhere/certificate.cer");
        subject.withParentResourceCertificatePublicationUri(publicationUri);
        subject.withSerial(BigInteger.TEN);

        subject.withSubjectDN(new X500Principal("CN=subject"));
        subject.withIssuerDN(resourceCertificate.getSubject());

        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        subject.withResources(new IpResourceSet());
        subject.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));

        // when
        X509ResourceCertificate certificate = subject.build();

        // then
        assertEquals(BigInteger.TEN, certificate.getSerialNumber());
        assertEquals(resourceCertificate.getSubject(), certificate.getIssuer());
        assertEquals(crlUri, certificate.getCrlUri());
        assertEquals(manifestUri, certificate.getSubjectInformationAccess()[0].getLocation());
        assertEquals(publicationUri, certificate.getAuthorityInformationAccess()[0].getLocation());
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutSerialNumber() {
        // given
        createValidEeBuilder();
        subject.withSerial(null);

        // when
        buildOrFail();
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutResourceCertificatePublicationUri() {
        // given
        createValidEeBuilder();
        subject.withParentResourceCertificatePublicationUri(null);

        // when
        buildOrFail();
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutValidityPeriod() {
        // given
        createValidEeBuilder();
        subject.withValidityPeriod(null);

        buildOrFail();
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutIssuer() {
        // given
        createValidEeBuilder();
        subject.withIssuerDN(null);

        buildOrFail();
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutSigningKeyPair() {
        // given
        createValidEeBuilder();
        subject.withSigningKeyPair(null);

        buildOrFail();
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutManifestUri() {
        // given
        createValidEeBuilder();
        subject.withCorrespondingCmsPublicationPoint(null);

        buildOrFail();
    }

    @Test(expected = NullPointerException.class)
    public void shouldNotBuildWithoutCrlPublicationUri() {
        // given
        createValidEeBuilder();
        subject.withCrlUri(null);

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
        subject.withCrlUri(crlUri);

        URI manifestUri = URI.create("rsync://somewhere/certificate.mft");
        subject.withCorrespondingCmsPublicationPoint(manifestUri);

        subject.withSigningKeyPair(KeyPairFactoryTest.TEST_KEY_PAIR);
        subject.withIssuerDN(resourceCertificate.getSubject());

        var now = Instant.now();
        subject.withValidityPeriod(new ValidityPeriod(now, now.plusSeconds(5)));

        URI publicationUri = URI.create("rsync://somewhere/certificate.cer");
        subject.withParentResourceCertificatePublicationUri(publicationUri);

        subject.withSerial(BigInteger.TEN);
    }

}
