/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.cms.manifest;

import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.manifest.ManifestCms.FileContentSpecification;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationOptions;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationStatus;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.bouncycastle.asn1.x509.KeyUsage;
import org.easymock.IAnswer;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;
import org.joda.time.DateTimeZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class ManifestCmsTest{

	private static final URI ROOT_CERTIFICATE_LOCATION = URI.create("rsync://foo.host/bar/bar.cer");
	private static final URI ROOT_SIA_MANIFEST_RSYNC_LOCATION = URI.create("rsync://foo.host/bar/manifest.mft");
	private static final URI ROOT_MANIFEST_CRL_LOCATION = URI.create("rsync://foo.host/bar/bar.crl");

	// Root certificate
	private static final IpResourceSet ROOT_RESOURCE_SET = IpResourceSet.parse("10.0.0.0/8, 192.168.0.0/16, ffce::/16, AS21212");
	private static final KeyPair ROOT_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

	// Manifest EE certificate
    public static final KeyPair MANIFEST_KEY_PAIR = KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
	private static final X500Principal MANIFEST_DN = new X500Principal("CN=manifest");

	// Manifest data
	private static byte[] FOO_CONTENTS = { 'a', 'b', 'c' };
	private static byte[] BAR_CONTENTS = { 'd', 'e', 'f' };

	private static final DateTime THIS_UPDATE_TIME = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC);
	private static final DateTime NEXT_UPDATE_TIME = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC);

	private CrlLocator crlLocator;
    private ManifestCms subject;
    private X509ResourceCertificate rootCertificate;

    private static final ValidationOptions VALIDATION_OPTIONS = new ValidationOptions();

    public static ManifestCms getRootManifestCms() {
        ManifestCmsBuilder builder = getRootManifestBuilder();
        builder.addFile("foo1", FOO_CONTENTS);
        builder.addFile("BaR", BAR_CONTENTS);
        return builder.build(MANIFEST_KEY_PAIR.getPrivate());
	}

    @Before
    public void setUp() {
        DateTimeUtils.setCurrentMillisFixed(THIS_UPDATE_TIME.getMillis());

        rootCertificate = getRootResourceCertificate();
        crlLocator = createMock(CrlLocator.class);
        subject = getRootManifestCms();
    }

    @After
    public void tearDown() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void shouldVerifySignature() {
        assertTrue(subject.signedBy(subject.getCertificate()));
    }

    @Test
    public void shouldVerifyFileContents() {
        assertTrue(subject.verifyFileContents("foo1", FOO_CONTENTS));
        assertFalse(subject.verifyFileContents("BaR", FOO_CONTENTS));

        FileContentSpecification spec = subject.getFileContentSpecification("BaR");
        assertTrue(spec.isSatisfiedBy(BAR_CONTENTS));
        assertFalse(spec.isSatisfiedBy(FOO_CONTENTS));
    }

    @Test
    public void shouldValidateManifestCms() {
        X509Crl crl = getRootCrl();
    	IpResourceSet resources = rootCertificate.getResources();

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources);
    	ValidationResult result = new ValidationResult();

    	expect(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).andReturn(crl);
    	replay(crlLocator);

    	subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

    	verify(crlLocator);

    	assertEquals(0, result.getFailuresForCurrentLocation().size());
    	assertFalse(result.hasFailures());
    }

    @Test
    public void shouldNotValidateWithInvalidCrl() {
    	IpResourceSet resources = rootCertificate.getResources();

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources);
    	final ValidationResult result = new ValidationResult();
    	result.setLocation(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION));
    	final ValidationLocation rootMftCrlValidationLocation = new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION);

    	expect(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).andAnswer(new IAnswer<X509Crl>() {
    	    @Override
            public X509Crl answer() throws Throwable {
    	        assertEquals(rootMftCrlValidationLocation, result.getCurrentLocation());
    	        result.rejectIfFalse(false, ValidationString.CRL_SIGNATURE_VALID);
    	        return null;
    	    }
    	});
    	replay(crlLocator);

    	subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

    	verify(crlLocator);

    	assertTrue(result.hasFailureForCurrentLocation());
    	assertEquals(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), result.getCurrentLocation());
		assertTrue(result.hasFailureForLocation(rootMftCrlValidationLocation));
		assertTrue(result.getAllValidationChecksForLocation(new ValidationLocation(ROOT_MANIFEST_CRL_LOCATION)).contains(new ValidationCheck(ValidationStatus.ERROR, ValidationString.CRL_SIGNATURE_VALID)));
    }

    @Test
    public void shouldWarnWhenManifestIsStale() {
        X509Crl crl = getRootCrl();

        DateTimeUtils.setCurrentMillisFixed(NEXT_UPDATE_TIME.plusDays(1).getMillis());

    	IpResourceSet resources = rootCertificate.getResources();

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources);

        ValidationOptions options = new ValidationOptions();
        options.setMaxStaleDays(Integer.MAX_VALUE);
        ValidationResult result = new ValidationResult();

    	expect(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).andReturn(crl);
    	replay(crlLocator);

    	subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

    	verify(crlLocator);

    	assertFalse(result.hasFailures());
    	assertEquals(0, result.getFailuresForCurrentLocation().size());

    	assertEquals(
    		new ValidationCheck(ValidationStatus.WARNING, ValidationString.NOT_VALID_AFTER, NEXT_UPDATE_TIME.toString()),
    		result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.NOT_VALID_AFTER)
		);
    }


    @Test
    public void shouldRejectWhenManifestIsTooStale() {
        X509Crl crl = getRootCrl();

        DateTimeUtils.setCurrentMillisFixed(NEXT_UPDATE_TIME.plusDays(1).getMillis());

        IpResourceSet resources = rootCertificate.getResources();

        CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources);

        ValidationOptions options = new ValidationOptions();
        options.setMaxStaleDays(0);
        ValidationResult result = new ValidationResult();

        expect(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).andReturn(crl);
        replay(crlLocator);

        subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, options, result);

        verify(crlLocator);

        assertTrue(result.hasFailures());

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.NOT_VALID_AFTER, NEXT_UPDATE_TIME.toString()),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.NOT_VALID_AFTER)
        );

        assertEquals(
                new ValidationCheck(ValidationStatus.ERROR, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME),
                result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME)
        );
    }


    @Test
    public void shouldWarnAboutInconsistentValidityTimes() {
    	ManifestCms mft = getManifestWithInconsistentValidityTimes();

        X509Crl crl = getRootCrl();
    	IpResourceSet resources = rootCertificate.getResources();

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources);
    	ValidationResult result = new ValidationResult();
    	result.setLocation(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION));

    	expect(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).andReturn(crl);
    	replay(crlLocator);

    	mft.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, VALIDATION_OPTIONS, result);

    	verify(crlLocator);

    	assertEquals(0, result.getFailuresForCurrentLocation().size());
    	assertFalse(result.hasFailures());

    	assertEquals(
        		new ValidationCheck(ValidationStatus.WARNING, ValidationString.MANIFEST_VALIDITY_TIMES_INCONSISTENT),
        		result.getResult(new ValidationLocation(ROOT_SIA_MANIFEST_RSYNC_LOCATION), ValidationString.MANIFEST_VALIDITY_TIMES_INCONSISTENT)
    		);

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
		builder.withThisUpdateTime(new DateTime());
		builder.withNextUpdateTime(new DateTime().plusHours(8));
		builder.withNumber(BigInteger.TEN);
		builder.withAuthorityKeyIdentifier(ROOT_KEY_PAIR.getPublic());
		builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
		return builder;
	}

    private static ManifestCms getManifestWithInconsistentValidityTimes() {
    	ManifestCmsBuilder builder = getRootManifestBuilder();
    	builder.withCertificate(getManifestEEResourceCertificateBuilder(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME.plusDays(1))).build());
    	return builder.build(MANIFEST_KEY_PAIR.getPrivate());
    }

    public static ManifestCmsBuilder getRootManifestBuilder() {
		ManifestCmsBuilder builder = new ManifestCmsBuilder();
		builder.withCertificate(getManifestEEResourceCertificateBuilder(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME)).build());
		builder.withManifestNumber(BigInteger.valueOf(68));
		builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
		builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
		return builder;
	}

	private static X509ResourceCertificateBuilder getManifestEEResourceCertificateBuilder(ValidityPeriod validityPeriod) {
		X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

		builder.withCa(false);
		builder.withKeyUsage(KeyUsage.digitalSignature);
		builder.withSubjectDN(MANIFEST_DN);
		builder.withIssuerDN(X509ResourceCertificateTest.TEST_SELF_SIGNED_CERTIFICATE_NAME);
		builder.withSerial(BigInteger.ONE);

		builder.withPublicKey(MANIFEST_KEY_PAIR.getPublic());
		builder.withSigningKeyPair(ROOT_KEY_PAIR);
		builder.withResources(InheritedIpResourceSet.getInstance());
		builder.withValidityPeriod(validityPeriod);
		builder.withCrlDistributionPoints(ROOT_MANIFEST_CRL_LOCATION);
		return builder;
	}

}
