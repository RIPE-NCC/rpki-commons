package net.ripe.rpki.commons.crypto.cms.manifest;

import com.google.common.collect.Lists;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms.FileContentSpecification;
import net.ripe.rpki.commons.crypto.crl.CrlLocator;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.validation.*;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.mockito.stubbing.Answer;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;


public class ManifestCmsTest {

    private static final URI ROOT_CERTIFICATE_LOCATION = URI.create("rsync://foo.host/bar/bar.cer");
    private static final URI ROOT_SIA_MANIFEST_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/manifest.mft");
    private static final URI ROOT_MANIFEST_CRL_LOCATION = URI.create("rsync://foo.host/bar/bar.crl");

    // Root certificate
    private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
    public static final KeyPair ROOT_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    // Manifest EE certificate
    public static final KeyPair MANIFEST_KEY_PAIR = KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
    private static final X500Principal MANIFEST_DN = new X500Principal("CN=manifest");

    // Manifest data
    private static final byte[] FILE1_CONTENTS = {'a', 'b', 'c'};
    private static final byte[] FILE2_CONTENTS = {'d', 'e', 'f'};

    private static final Instant THIS_UPDATE_TIME = Instant.parse("2008-09-01T22:43:29Z");
    private static final Instant MFT_EE_NOT_BEFORE = THIS_UPDATE_TIME.minusSeconds(5 * 60);
    private static final Instant NEXT_UPDATE_TIME = THIS_UPDATE_TIME.plusSeconds(24 * 60 * 60);
    private static final Instant MFT_EE_NOT_AFTER = THIS_UPDATE_TIME.plusSeconds(7 * 24 * 60 * 60);

    // Test Manifest entries
    private static final Map<String, byte[]> files = new HashMap<>();

    static {
        files.put("filename1.cer", FILE1_CONTENTS);
        files.put("filename2.roa", FILE2_CONTENTS);
    }

    private final Clock clock = Clock.fixed(THIS_UPDATE_TIME, ZoneOffset.UTC);
    private final ValidationResult validationResult = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION).withClock(clock);

    private CrlLocator crlLocator;
    private ManifestCms subject;
    private X509ResourceCertificate rootCertificate;

    private static final ValidationOptions VALIDATION_OPTIONS = ValidationOptions.strictValidation();

    public static ManifestCms getRootManifestCms() {
        ManifestCmsBuilder builder = getRootManifestBuilder();
        for (Entry<String, byte[]> entry : files.entrySet()) {
            builder.addFile(entry.getKey(), entry.getValue());
        }
        return builder.build(MANIFEST_KEY_PAIR.getPrivate());
    }

    @Before
    public void setUp() {
        rootCertificate = getRootResourceCertificate();
        crlLocator = mock(CrlLocator.class);
        subject = getRootManifestCms();
    }

    @Test
    public void shouldVerifySignature() {
        assertTrue(subject.signedBy(subject.getCertificate()));
    }

    @Test
    public void shouldVerifyFileContents() {
        assertTrue(subject.verifyFileContents("filename1.cer", FILE1_CONTENTS));
        assertFalse(subject.verifyFileContents("filename2.roa", FILE1_CONTENTS));

        FileContentSpecification spec = subject.getFileContentSpecification("filename2.roa");
        assertTrue(spec.isSatisfiedBy(FILE2_CONTENTS));
        assertFalse(spec.isSatisfiedBy(FILE1_CONTENTS));
    }

    @Test
    public void shouldValidateManifestCms() {
        X509Crl crl = getRootCrl();
        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, validationResult);

        assertEquals(0, validationResult.getFailuresForCurrentLocation().size());
        assertFalse(validationResult.hasFailures());
    }

    @Test
    public void shouldNotValidateWithInvalidCrl() {
        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));
        validationResult.setLocation(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION));
        final ValidationLocation rootMftCrlValidationLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenAnswer((Answer<X509Crl>) invocationOnMock -> {
            assertEquals(rootMftCrlValidationLocation, validationResult.getCurrentLocation());
            validationResult.rejectIfFalse(false, ValidationString.CRL_SIGNATURE_VALID);
            return null;
        });

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, validationResult);

        assertTrue(validationResult.hasFailureForCurrentLocation());
        assertEquals(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), validationResult.getCurrentLocation());
        assertTrue(validationResult.hasFailureForLocation(rootMftCrlValidationLocation));
        assertTrue(validationResult.getAllValidationChecksForLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION)).contains(new ValidationCheck(ValidationStatus.ERROR, ValidationString.CRL_SIGNATURE_VALID)));
    }

    @Test
    public void shouldWarnWhenManifestIsStale() {
        X509Crl crl = getRootCrl();

        validationResult.withClock(Clock.fixed(NEXT_UPDATE_TIME.plus(1, ChronoUnit.DAYS), ZoneOffset.UTC));

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO, Duration.ofDays(100 * 365));

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, validationResult);

        assertFalse("" + validationResult.getFailuresForAllLocations(), validationResult.hasFailures());
        assertEquals(0, validationResult.getFailuresForCurrentLocation().size());


        assertEquals(
                new ValidationCheck(ValidationStatus.WARNING, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectWhenManifestIsTooStaleDueToNegativeGracePeriod() {
        X509Crl crl = getRootCrl();

        validationResult.withClock(Clock.fixed(NEXT_UPDATE_TIME.minus(1, ChronoUnit.DAYS), ZoneOffset.UTC));

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO, Duration.ofDays(-2));

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, validationResult);

        assertTrue(validationResult.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectWhenThisUpdateTimeIsNotBeforeNextUpdateTime() {
        X509Crl crl = getRootCrl();
        validationResult.withClock(Clock.fixed(NEXT_UPDATE_TIME.plus(1, ChronoUnit.DAYS), ZoneOffset.UTC));

        subject = getRootManifestBuilder().withThisUpdateTime(NEXT_UPDATE_TIME.plusSeconds(1)).build(MANIFEST_KEY_PAIR.getPrivate());

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        subject.validateWithCrl(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toASCIIString(), context, ValidationOptions.strictValidation(), validationResult, crl);

        assertTrue(validationResult.hasFailures());
        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_THIS_UPDATE_TIME_BEFORE_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.plusSeconds(1).toString(), NEXT_UPDATE_TIME.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_THIS_UPDATE_TIME_BEFORE_NEXT_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectWhenManifestIsTooStale() {
        X509Crl crl = getRootCrl();

        validationResult.withClock(Clock.fixed(NEXT_UPDATE_TIME.plus(1, ChronoUnit.DAYS), ZoneOffset.UTC));
        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO,Duration.ZERO);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, validationResult);

        assertTrue(validationResult.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }

    /**
     * EE certificate is expired. Manifest is in grace period.
     */
    @Test
    public void shouldRejectWhenCertificateIsExpired() {
        X509Crl crl = getRootCrl();

        validationResult.withClock(Clock.fixed(NEXT_UPDATE_TIME.plus(8, ChronoUnit.DAYS), ZoneOffset.UTC));
        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO, Duration.ofDays(100));

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, validationResult);

        assertTrue(validationResult.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.WARNING, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.NOT_VALID_AFTER, MFT_EE_NOT_AFTER.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.NOT_VALID_AFTER)
        );
    }

    /**
     * This update in future. EE certificate in validity window (notBefore is 5 minutes before THIS_UPDATE_TIME).
     */
    @Test
    public void shouldRejectWhenThisUpdateInFuture() {
        X509Crl crl = getRootCrl();

        validationResult.withClock(Clock.fixed(THIS_UPDATE_TIME.minus(1, ChronoUnit.SECONDS), ZoneOffset.UTC));
        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.backCompatibleRipeNccValidator();

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, validationResult)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, validationResult);

        assertTrue(validationResult.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_BEFORE_THIS_UPDATE_TIME, THIS_UPDATE_TIME.toString()),
                validationResult.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_BEFORE_THIS_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectFileNamesThatEscapeRepository() {
        X509Crl crl = getRootCrl();
        Clock clock = Clock.fixed(NEXT_UPDATE_TIME.minus(1, ChronoUnit.SECONDS), ZoneOffset.UTC);

        ManifestCmsBuilder builder = getRootManifestBuilder();
        builder.addFile("this-one-is-ok.roa", new byte[0]);
        builder.addFile("non-empty-extension-required.", new byte[0]);
        builder.addFile("multiple.dots.not.allowed", new byte[0]);
        builder.addFile("underscore_is_also_allowed_since_there_are_published_objects.roa", new byte[0]);
        builder.addFile("extension-must-be-lowercase.CER", new byte[0]);
        builder.addFile("only-letters-allowed-for-extension.123", new byte[0]);
        builder.addFile("", new byte[0]); // empty is not ok
        builder.addFile("   ", new byte[0]); // blank is not ok
        builder.addFile("\0", new byte[0]); // control character not ok
        builder.addFile(".", new byte[0]);
        builder.addFile("..", new byte[0]);
        builder.addFile("cannot-contain-a/slash.cer", new byte[0]);

        subject = builder.build(MANIFEST_KEY_PAIR.getPrivate());

        IpResourceSet resources = rootCertificate.getResources();
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.strictValidation();
        ValidationResult result = validationResult.withClock(clock);

        subject.validateWithCrl(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, options, result, crl);

        assertTrue(result.hasFailures());

        assertEquals(
                new ValidationCheck(
                        ValidationStatus.ERROR,
                        ValidationString.MANIFEST_ENTRY_FILE_NAME_IS_RELATIVE,
                        ", \\u0000,    , ., .., cannot-contain-a/slash.cer, extension-must-be-lowercase.CER, multiple.dots.not.allowed, non-empty-extension-required., only-letters-allowed-for-extension.123"
                ),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_ENTRY_FILE_NAME_IS_RELATIVE)
        );
    }

    @Test
    public void shouldMatchFiles() {
        ManifestCms mft = getRootManifestCms();
        assertTrue(mft.matchesFiles(files));
    }

    @Test
    public void shouldNotMatchIfFilesMissing() {
        ManifestCms mft = getRootManifestCms();
        Map<String, byte[]> emptyFiles = Collections.emptyMap();
        assertFalse(mft.matchesFiles(emptyFiles));
    }

    @Test
    public void shouldNotMatchIfAdditionalFilesPresent() {
        ManifestCms mft = getRootManifestCms();
        Map<String, byte[]> wrongFiles = new HashMap<>(files);
        wrongFiles.put("newfile", FILE1_CONTENTS);
        assertFalse(mft.matchesFiles(wrongFiles));
    }

    @Test
    public void shouldNotMatchIfFileContentChanged() {
        ManifestCms mft = getRootManifestCms();
        Map<String, byte[]> wrongFiles = new HashMap<>(files);
        wrongFiles.put("filename2", FILE1_CONTENTS);
        assertFalse(mft.matchesFiles(wrongFiles));
    }

    @Test
    public void shouldPastValidityTimeForCmsBeTheSameAsTheCertificate() {
        ManifestCms subject = getRootManifestCms();
        assertEquals(subject.getCertificate().isPastValidityTime(Instant.now()), subject.isPastValidityTime(Instant.now()));
    }

    @Test
    public void shouldBeRevoked() {
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate);
        final ValidationResult result = validationResult;

        X509Crl crl = getRootCrlBuilder()
                .addEntry(subject.getCertificate().getSerialNumber(), Instant.now().minus(1, ChronoUnit.MINUTES))
                .build(ROOT_KEY_PAIR.getPrivate());

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertTrue(subject.isRevoked());
    }



    private X509Crl getRootCrl() {
        return getRootCrlBuilder().build(ROOT_KEY_PAIR.getPrivate());
    }

    private X509ResourceCertificate getRootResourceCertificate() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();

        builder.withResources(ROOT_RESOURCE_SET);
        builder.withPublicKey(ROOT_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(ROOT_KEY_PAIR);

        X509CertificateInformationAccessDescriptor[] descriptors = {
                new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_RPKI_MANIFEST, ROOT_SIA_MANIFEST_RSYNC_LOCATION),
        };
        builder.withSubjectInformationAccess(descriptors);
        builder.withCrlDistributionPoints(ROOT_MANIFEST_CRL_LOCATION);
        return builder.build();
    }

    private X509CrlBuilder getRootCrlBuilder() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(X509ResourceCertificateTest.TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withThisUpdateTime(NEXT_UPDATE_TIME.minus(24, ChronoUnit.HOURS));
        builder.withNextUpdateTime(NEXT_UPDATE_TIME.plus(24, ChronoUnit.HOURS));
        builder.withNumber(BigInteger.TEN);
        builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

    public static ManifestCmsBuilder getRootManifestBuilder() {
        return getRootManifestBuilder(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME));
    }

    public static ManifestCmsBuilder getRootManifestBuilder(ValidityPeriod validityPeriod) {
        ManifestCmsBuilder builder = new ManifestCmsBuilder();
        builder.withCertificate(getManifestEEResourceCertificateBuilder().build());
        builder.withManifestNumber(BigInteger.valueOf(68));
        builder.withThisUpdateTime(validityPeriod.notValidBefore()).withNextUpdateTime(validityPeriod.notValidAfter());
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
        return builder;
    }

    private static X509ResourceCertificateBuilder getManifestEEResourceCertificateBuilder() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withCa(false);
        builder.withKeyUsage(KeyUsage.digitalSignature);
        builder.withSubjectDN(MANIFEST_DN);
        builder.withIssuerDN(X509ResourceCertificateTest.TEST_SELF_SIGNED_CERTIFICATE_NAME);
        builder.withSerial(BigInteger.ONE);

        builder.withPublicKey(MANIFEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(ROOT_KEY_PAIR);
        builder.withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class));
        builder.withValidityPeriod(new ValidityPeriod(MFT_EE_NOT_BEFORE, MFT_EE_NOT_AFTER));
        builder.withCrlDistributionPoints(ROOT_MANIFEST_CRL_LOCATION);
        builder.withSubjectInformationAccess(
                new X509CertificateInformationAccessDescriptor(ID_AD_SIGNED_OBJECT, ROOT_SIA_MANIFEST_RSYNC_LOCATION)
        );
        return builder;
    }

}
