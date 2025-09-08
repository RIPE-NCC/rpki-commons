package net.ripe.rpki.commons.provisioning.x509.pkcs10;

import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.security.KeyPair;

import static org.junit.Assert.*;


public class RpkiCaCertificateRequestBuilderParserTest {

    @Test
    public void shouldRoundTripBuildParseRpkiCaCertRequest() throws RpkiCaCertificateRequestParserException {

        RpkiCaCertificateRequestBuilder requestBuilder = new RpkiCaCertificateRequestBuilder();

        URI caRepositoryUri = URI.create("rsync://host/module/subdir/");
        URI manifestUri = URI.create("rsync://host/module/subdir/subject.mft");
        X500Principal subject = new X500Principal("CN=subject");
        KeyPair keyPair = PregeneratedKeyPairFactory.getRsaInstance().generate();

        requestBuilder.withCaRepositoryUri(caRepositoryUri);
        requestBuilder.withManifestUri(manifestUri);
        requestBuilder.withSubject(subject);
        PKCS10CertificationRequest pkcs10Request = requestBuilder.build(keyPair);

        assertNotNull(pkcs10Request);

        RpkiCaCertificateRequestParser requestParser = new RpkiCaCertificateRequestParser(pkcs10Request);

        assertEquals(caRepositoryUri, requestParser.getCaRepositoryUri());
        assertEquals(manifestUri, requestParser.getManifestUri());
        assertEquals(keyPair.getPublic(), requestParser.getPublicKey());
    }

    @Test
    public void shouldBuildParseEncodedRpkiCaCertRequest() throws Exception {

        PKCS10CertificationRequest pkcs10Request = createRpkiCaCertificateRequest();

        assertNotNull(pkcs10Request);

        PKCS10CertificationRequest decodedPkcs10Request = new PKCS10CertificationRequest(pkcs10Request.getEncoded());

        RpkiCaCertificateRequestParser requestParser = new RpkiCaCertificateRequestParser(decodedPkcs10Request);

        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_REPO_URI, requestParser.getCaRepositoryUri());
        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_MFT_URI, requestParser.getManifestUri());
        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_NOTIFICATION_URI, requestParser.getNotificationUri());
        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_KEYPAIR.getPublic(), requestParser.getPublicKey());
    }

    public static PKCS10CertificationRequest createRpkiCaCertificateRequest() {
        RpkiCaCertificateRequestBuilder requestBuilder = new RpkiCaCertificateRequestBuilder();
        requestBuilder.withCaRepositoryUri(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_REPO_URI);
        requestBuilder.withManifestUri(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_MFT_URI);
        requestBuilder.withNotificationUri(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_NOTIFICATION_URI);
        requestBuilder.withSubject(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_SUBJECT);
        PKCS10CertificationRequest pkcs10Request = requestBuilder.build(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_KEYPAIR);
        return pkcs10Request;
    }

}
