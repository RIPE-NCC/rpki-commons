package net.ripe.commons.provisioning.x509.pkcs10;

import static net.ripe.commons.provisioning.ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_KEYPAIR;
import static net.ripe.commons.provisioning.ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_MFT_URI;
import static net.ripe.commons.provisioning.ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_REPO_URI;
import static net.ripe.commons.provisioning.ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_SUBJECT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.URI;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.util.KeyPairFactory;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.junit.Test;


public class RpkiCaCertificateRequestBuilderParserTest {
    
    @Test
    public void shouldRoundTripBuildParseRpkiCaCertRequest() throws RpkiCaCertificateRequestParserException {
    
        RpkiCaCertificateRequestBuilder requestBuilder = new RpkiCaCertificateRequestBuilder();
        
        URI caRepositoryUri = URI.create("rsync://host/module/subdir/");
        URI manifestUri = URI.create("rsync://host/module/subdir/subject.mft");
        X500Principal subject = new X500Principal("CN=subject");
        KeyPair keyPair = KeyPairFactory.getInstance().generate(2048, "SunRsaSign");
        
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
    public void shouldBuildParseEncodedRpkiCaCertRequest() throws RpkiCaCertificateRequestParserException {
        
        PKCS10CertificationRequest pkcs10Request = createRpkiCaCertificateRequest();
        
        assertNotNull(pkcs10Request);
        
        PKCS10CertificationRequest decodedPkcs10Request = new PKCS10CertificationRequest(pkcs10Request.getEncoded());
        
        RpkiCaCertificateRequestParser requestParser = new RpkiCaCertificateRequestParser(decodedPkcs10Request);
        
        assertEquals(RPKI_CA_CERT_REQUEST_CA_REPO_URI, requestParser.getCaRepositoryUri());
        assertEquals(RPKI_CA_CERT_REQUEST_CA_MFT_URI, requestParser.getManifestUri());
        assertEquals(RPKI_CA_CERT_REQUEST_KEYPAIR.getPublic(), requestParser.getPublicKey());
    }

    public static PKCS10CertificationRequest createRpkiCaCertificateRequest() {
        RpkiCaCertificateRequestBuilder requestBuilder = new RpkiCaCertificateRequestBuilder();
        requestBuilder.withCaRepositoryUri(RPKI_CA_CERT_REQUEST_CA_REPO_URI);
        requestBuilder.withManifestUri(RPKI_CA_CERT_REQUEST_CA_MFT_URI);
        requestBuilder.withSubject(RPKI_CA_CERT_REQUEST_CA_SUBJECT);
        PKCS10CertificationRequest pkcs10Request = requestBuilder.build(RPKI_CA_CERT_REQUEST_KEYPAIR);
        return pkcs10Request;
    }

}
