package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.joda.time.DateTime;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.Optional;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.*;

public class ASProviderAttestationCmsTest {


    private static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;
    private static final X500Principal TEST_DN = new X500Principal("CN=issuer");
    private static final URI TEST_LOCATION = URI.create("rsync://certificate/repository/filename.asa");
    private static final URI TEST_CA_LOCATION = URI.create("rsync://certificate/repository/ca.cer");
    private static final BigInteger ROA_CERT_SERIAL = BigInteger.TEN;

    private static final ImmutableSortedSet<ProviderAS> PROVIDER_AS_SET = ImmutableSortedSet.<ProviderAS>naturalOrder()
        .add(new ProviderAS(Asn.parse("AS65001"), Optional.empty()))
        .add(new ProviderAS(Asn.parse("AS65002"), Optional.of(AddressFamily.IPV4)))
        .build();

    private static final Asn CUSTOMER_ASN = Asn.parse("AS65000");

    @Test
    public void should_parse_aspa() throws IOException {
        String path = "src/test/resources/conformance/root/aspa-bm.asa";
        byte[] bytes = FileUtils.readFileToByteArray(new File(path));
        ValidationResult result = ValidationResult.withLocation("aspa-bm.asa");
        ASProviderAttestationCmsParser parser = new ASProviderAttestationCmsParser();
        parser.parse(result, bytes);

        assertFalse("" + result.getFailuresForAllLocations(), result.hasFailures());
        ASProviderAttestationCms aspa = parser.getASProviderAttestationCms();
        assertEquals(Asn.parse("AS65000"), aspa.getCustomerAsn());
        assertEquals(
            ImmutableSortedSet.<ProviderAS>naturalOrder()
                .add(new ProviderAS(Asn.parse("AS65001"), Optional.empty()))
                .add(new ProviderAS(Asn.parse("AS65002"), Optional.of(AddressFamily.IPV4)))
                .build(),
            aspa.getProviderASSet()
        );
    }

    @Test
    public void should_generate_aspa() {
        ASProviderAttestationCms cms = createAspa();
        assertEquals(0, cms.getVersion());
        assertEquals(CUSTOMER_ASN, cms.getCustomerAsn());
        assertEquals(PROVIDER_AS_SET, cms.getProviderASSet());
    }

    public static ASProviderAttestationCms createAspa() {
        ASProviderAttestationCmsBuilder builder = new ASProviderAttestationCmsBuilder();
        builder.withCertificate(createCertificate(new IpResourceSet(CUSTOMER_ASN)));
        builder.withCustomerAsn(CUSTOMER_ASN);
        builder.withProviderASSet(
            PROVIDER_AS_SET
        );
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    private static X509ResourceCertificate createCertificate(IpResourceSet resources) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(ROA_CERT_SERIAL);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        final DateTime now = UTC.dateTime();
        builder.withKeyUsage(KeyUsage.digitalSignature);
        builder.withValidityPeriod(new ValidityPeriod(now.minusMinutes(1), now.plusYears(1)));
        builder.withResources(resources);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_LOCATION));
        builder.withAuthorityInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, TEST_CA_LOCATION));
        return builder.build();
    }

}