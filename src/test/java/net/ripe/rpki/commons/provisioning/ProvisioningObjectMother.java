package net.ripe.rpki.commons.provisioning;

import lombok.SneakyThrows;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import net.ripe.rpki.commons.provisioning.identity.IdentitySerializerException;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.error.RequestNotPerformedResponsePayloadSerializerTest;
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload;
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadSerializerTest;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder;
import net.ripe.rpki.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadBuilder;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest;
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilderParserTest;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509CRL;

public class ProvisioningObjectMother {

    public static final KeyPair TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    public static final KeyPair TEST_KEY_PAIR_2 = PregeneratedKeyPairFactory.getInstance().generate();
    public static final String DEFAULT_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    public static final KeyPair SECOND_TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    public static final X509CRL CRL = generateCrl();

    public static String PARENT_HANDLE = "test-parent-handle";
    public static String CHILD_HANDLE = "test-child-handle";

    public static URI RPKI_CA_CERT_REQUEST_CA_REPO_URI = URI.create("rsync://host/module/subdir/");
    public static URI RPKI_CA_CERT_REQUEST_CA_MFT_URI = URI.create("rsync://host/module/subdir/subject.mft");
    public static URI RPKI_CA_CERT_REQUEST_CA_CRL_URI = URI.create("rsync://host/module/subdir/subject.crl");
    public static URI RPKI_CA_CERT_REQUEST_CA_NOTIFICATION_URI = URI.create("http://host:7788/module/subdir/notification.xml");

    public static final X509ResourceCertificate X509_CA = generateX509();

    public static X500Principal RPKI_CA_CERT_REQUEST_CA_SUBJECT = new X500Principal("CN=subject");
    public static KeyPair RPKI_CA_CERT_REQUEST_KEYPAIR = PregeneratedKeyPairFactory.getInstance().generate();
    public static PKCS10CertificationRequest RPKI_CA_CERT_REQUEST = RpkiCaCertificateRequestBuilderParserTest.createRpkiCaCertificateRequest();
    private static final CertificateIssuanceRequestPayload RPKI_CA_CERT_REQUEST_PAYLOAD = CertificateIssuanceRequestPayloadSerializerTest.createCertificateIssuanceRequestPayloadForPkcs10Request(RPKI_CA_CERT_REQUEST);

    public static ResourceClassListQueryPayload RESOURCE_CLASS_LIST_QUERY_PAYLOAD = createResourceListQueryPayload();

    private static X509ResourceCertificate generateX509() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withCa(true);
        builder.withKeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(2011, 3, 1, 0, 0, 0, 0, DateTimeZone.UTC);
        builder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(5)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        builder.withCrlDistributionPoints(RPKI_CA_CERT_REQUEST_CA_CRL_URI);
        builder.withSubjectInformationAccess(
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY, RPKI_CA_CERT_REQUEST_CA_REPO_URI),
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, RPKI_CA_CERT_REQUEST_CA_MFT_URI)
        );
        return builder.build();
    }

    private static X509CRL generateCrl() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=nl.bluelight"));
        builder.withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic());
        DateTime now = UTC.dateTime();
        builder.withThisUpdateTime(now);
        builder.withNextUpdateTime(now.plusHours(24));
        builder.withNumber(BigInteger.TEN);

        return builder.build(TEST_KEY_PAIR.getPrivate()).getCrl();
    }

    @SneakyThrows
    public static ProvisioningCmsObject createResourceClassListQueryProvisioningCmsObject() {
        return createCmsForPayload(createResourceListQueryPayload());
    }

    @SneakyThrows
    public static ProvisioningCmsObject createResourceCertificateSignRequestProvisioningCmsObject() {
        return createCmsForPayload(RPKI_CA_CERT_REQUEST_PAYLOAD);
    }

    @SneakyThrows
    public static ProvisioningCmsObject createRequestNotPerformedResponseObject() {
        return createCmsForPayload(RequestNotPerformedResponsePayloadSerializerTest.NOT_PERFORMED_PAYLOAD);
    }

    public static ProvisioningCmsObject createRevocationRequestCmsObject() throws Exception {

        CertificateRevocationRequestPayloadBuilder revokePayloadBuilder = new CertificateRevocationRequestPayloadBuilder();
        revokePayloadBuilder.withClassName(RPKI_CA_CERT_REQUEST_PAYLOAD.getRequestElement().getClassName());
        revokePayloadBuilder.withPublicKey(RPKI_CA_CERT_REQUEST_KEYPAIR.getPublic());
        return createCmsForPayload(revokePayloadBuilder.build());
    }

    private static ProvisioningCmsObject createCmsForPayload(AbstractProvisioningPayload payloadXml) throws IdentitySerializerException {
        payloadXml.setSender(CHILD_HANDLE);
        payloadXml.setRecipient(PARENT_HANDLE);
        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withCrl(CRL)
                .withPayloadContent(payloadXml);
        return builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
    }

    private static ResourceClassListQueryPayload createResourceListQueryPayload() {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        return payloadBuilder.build();
    }

}
