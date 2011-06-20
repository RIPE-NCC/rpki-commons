package net.ripe.commons.provisioning;

import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.*;
import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509CRL;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactory;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import net.ripe.commons.provisioning.keypair.ProvisioningKeyPairGenerator;
import net.ripe.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload;
import net.ripe.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilderTest;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder;
import net.ripe.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilderParserTest;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.joda.time.DateTime;

public class ProvisioningObjectMother {

    public static final KeyPair TEST_KEY_PAIR = ProvisioningKeyPairGenerator.generate();
    public static final KeyPair TEST_KEY_PAIR_2 = ProvisioningKeyPairGenerator.generate();
    public static final String DEFAULT_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    public static KeyPair SECOND_TEST_KEY_PAIR = KeyPairFactory.getInstance().generate(512, DEFAULT_KEYPAIR_GENERATOR_PROVIDER);

    public static final X509CRL CRL = generateCrl();

    public static final X509ResourceCertificate X509_CA = generateX509();
    
    public static URI RPKI_CA_CERT_REQUEST_CA_REPO_URI = URI.create("rsync://host/module/subdir/");
    public static URI RPKI_CA_CERT_REQUEST_CA_MFT_URI = URI.create("rsync://host/module/subdir/subject.mft");
    
    public static X500Principal RPKI_CA_CERT_REQUEST_CA_SUBJECT = new X500Principal("CN=subject");
    public static KeyPair RPKI_CA_CERT_REQUEST_KEYPAIR = KeyPairFactory.getInstance().generate(2048, "SunRsaSign");
    public static PKCS10CertificationRequest RPKI_CA_CERT_REQUEST = RpkiCaCertificateRequestBuilderParserTest.createRpkiCaCertificateRequest();
    private static final CertificateIssuanceRequestPayload RPKI_CA_CERT_REQUEST_PAYLOAD = CertificateIssuanceRequestPayloadBuilderTest.createCertificateIssuanceRequestPayloadForPkcs10Request(RPKI_CA_CERT_REQUEST);
    
    public static ResourceClassListQueryPayload RESOURCE_CLASS_LIST_QUERY_PAYLOAD = createResourceListQueryPayload();

    private static X509ResourceCertificate generateX509() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(2011, 3, 1, 0, 0, 0, 0);
        builder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(5)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        return builder.build();
    }

    private static X509CRL generateCrl() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=nl.bluelight"));
        builder.withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic());
        DateTime now = new DateTime();
        builder.withThisUpdateTime(now);
        builder.withNextUpdateTime(now.plusHours(24));
        builder.withNumber(BigInteger.TEN);

        return builder.build(TEST_KEY_PAIR.getPrivate()).getCrl();
    }
    
    public static ProvisioningCmsObject createResourceClassListQueryProvisioningCmsObject() {
        return createCmsForQueryPayload(createResourceListQueryPayload());
    }
    
    public static ProvisioningCmsObject createResourceCertificateSignRequestProvisioningCmsObject() {
        return createCmsForQueryPayload(RPKI_CA_CERT_REQUEST_PAYLOAD);
    }
    
    private static ProvisioningCmsObject createCmsForQueryPayload(AbstractProvisioningPayload payloadXml) {
        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                .withCrl(CRL)
                .withCaCertificate(TEST_IDENTITY_CERT.getCertificate())
                .withPayloadContent(payloadXml);
        return builder.build(EE_KEYPAIR.getPrivate());
    }
    
    private static ResourceClassListQueryPayload createResourceListQueryPayload() {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        ResourceClassListQueryPayload payloadXml = payloadBuilder.build();
        return payloadXml;
    }
}
