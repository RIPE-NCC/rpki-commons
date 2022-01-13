/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
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
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationStatus;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
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
    private static byte[] FILE1_CONTENTS = {'a', 'b', 'c'};
    private static byte[] FILE2_CONTENTS = {'d', 'e', 'f'};

    private static final Instant THIS_UPDATE_TIME = OffsetDateTime.of(2008, 9, 1, 22, 43, 29, 0, ZoneOffset.UTC).toInstant();
    private static final Instant MFT_EE_NOT_BEFORE = THIS_UPDATE_TIME.minus(5, ChronoUnit.MINUTES);
    private static final Instant NEXT_UPDATE_TIME = THIS_UPDATE_TIME.plus(24, ChronoUnit.HOURS);
    private static final Instant MFT_EE_NOT_AFTER = THIS_UPDATE_TIME.plus(7, ChronoUnit.DAYS);

    // Test Manifest entries
    private static Map<String, byte[]> files = new HashMap<String, byte[]>();

    static {
        files.put("filename1.cer", FILE1_CONTENTS);
        files.put("filename2.roa", FILE2_CONTENTS);
    }

    private CrlLocator crlLocator;
    private ManifestCms subject;
    private X509ResourceCertificate rootCertificate;

    private static final Clock CLOCK = Clock.fixed(THIS_UPDATE_TIME, ZoneOffset.UTC);
    private static final ValidationOptions VALIDATION_OPTIONS = ValidationOptions.strictValidation().setClock(CLOCK);

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
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertEquals("" + result.getFailuresForAllLocations(), 0, result.getFailuresForCurrentLocation().size());
        assertFalse(result.hasFailures());
    }

    @Test
    public void shouldNotValidateWithInvalidCrl() {
        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));
        final ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);
        result.setLocation(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION));
        final ValidationLocation rootMftCrlValidationLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenAnswer(new Answer<X509Crl>() {
            @Override
            public X509Crl answer(InvocationOnMock invocationOnMock) throws Throwable {
                assertEquals(rootMftCrlValidationLocation, result.getCurrentLocation());
                result.rejectIfFalse(false, ValidationString.CRL_SIGNATURE_VALID);
                return null;
            }
        });

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

        assertTrue(result.hasFailureForCurrentLocation());
        assertEquals(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), result.getCurrentLocation());
        assertTrue(result.hasFailureForLocation(rootMftCrlValidationLocation));
        assertTrue(result.getAllValidationChecksForLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION)).contains(new ValidationCheck(ValidationStatus.ERROR, ValidationString.CRL_SIGNATURE_VALID)));
    }

    @Test
    public void shouldWarnWhenManifestIsStale() {
        X509Crl crl = getRootCrl();

        Clock clock = Clock.fixed(NEXT_UPDATE_TIME.plus(1, ChronoUnit.DAYS), ZoneOffset.UTC);

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO, Duration.ofDays(100 * 365)).setClock(clock);
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

        assertFalse("" + result.getFailuresForAllLocations(), result.hasFailures());
        assertEquals(0, result.getFailuresForCurrentLocation().size());


        assertEquals(
                new ValidationCheck(ValidationStatus.WARNING, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectWhenManifestIsTooStaleDueToNegativeGracePeriod() {
        X509Crl crl = getRootCrl();

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO, Duration.ofDays(-2));
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

        assertTrue(result.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectWhenThisUpdateTimeIsNotBeforeNextUpdateTime() {
        X509Crl crl = getRootCrl();

        subject = getRootManifestBuilder().withThisUpdateTime(NEXT_UPDATE_TIME.plusSeconds(1)).build(MANIFEST_KEY_PAIR.getPrivate());

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        subject.validateWithCrl(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toASCIIString(), context, ValidationOptions.strictValidation(), result, crl);

        assertTrue(result.hasFailures());
        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_THIS_UPDATE_TIME_BEFORE_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.plusSeconds(1).toString(), NEXT_UPDATE_TIME.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_THIS_UPDATE_TIME_BEFORE_NEXT_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectWhenManifestIsTooStale() {
        X509Crl crl = getRootCrl();

        Clock clock = Clock.fixed(NEXT_UPDATE_TIME.plus(1, ChronoUnit.DAYS), ZoneOffset.UTC);

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO,Duration.ZERO).setClock(clock);
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

        assertTrue(result.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }

    /**
     * EE certificate is expired. Manifest is in grace period.
     */
    @Test
    public void shouldRejectWhenCertificateIsExpired() {
        X509Crl crl = getRootCrl();

        Clock clock = Clock.fixed(NEXT_UPDATE_TIME.plus(8, ChronoUnit.DAYS), ZoneOffset.UTC);

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.withStaleConfigurations(Duration.ZERO, Duration.ofDays(100)).setClock(clock);
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

        assertTrue(result.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.WARNING, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, NEXT_UPDATE_TIME.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.NOT_VALID_AFTER, MFT_EE_NOT_AFTER.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.NOT_VALID_AFTER)
        );
    }

    /**
     * This update in future. EE certificate in validity window (notBefore is 5 minutes before THIS_UPDATE_TIME).
     */
    @Test
    public void shouldRejectWhenThisUpdateInFuture() {
        X509Crl crl = getRootCrl();

        Clock clock = Clock.fixed(THIS_UPDATE_TIME.minusSeconds(1), ZoneOffset.UTC);

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources, Lists.newArrayList(rootCertificate.getSubject().getName()));

        ValidationOptions options = ValidationOptions.backCompatibleRipeNccValidator().setClock(clock);
        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        when(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).thenReturn(crl);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

        assertTrue(result.hasFailures());

        assertEquals(
            "" + result.getFailuresForAllLocations(),
            new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_BEFORE_THIS_UPDATE_TIME, THIS_UPDATE_TIME.toString()),
            result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_BEFORE_THIS_UPDATE_TIME)
        );
    }

    @Test
    public void shouldRejectFileNamesThatEscapeRepository() {
        X509Crl crl = getRootCrl();

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

        ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

        subject.validateWithCrl(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, VALIDATION_OPTIONS, result, crl);

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
        Map<String, byte[]> wrongFiles = new HashMap<String, byte[]>(files);
        wrongFiles.put("newfile", FILE1_CONTENTS);
        assertFalse(mft.matchesFiles(wrongFiles));
    }

    @Test
    public void shouldNotMatchIfFileContentChanged() {
        ManifestCms mft = getRootManifestCms();
        Map<String, byte[]> wrongFiles = new HashMap<String, byte[]>(files);
        wrongFiles.put("filename2", FILE1_CONTENTS);
        assertFalse(mft.matchesFiles(wrongFiles));
    }

    @Test
    public void shouldPastValidityTimeForCmsBeTheSameAsTheCertificate() {
        ManifestCms subject = getRootManifestCms();
        assertEquals(subject.getCertificate().isPastValidityTime(), subject.isPastValidityTime());
    }

    @Test
    public void shouldBeRevoked() {
        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate);
        final ValidationResult result = ValidationResult.withLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

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
        builder.withThisUpdateTime(validityPeriod.getNotValidBefore()).withNextUpdateTime(validityPeriod.getNotValidAfter());
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
