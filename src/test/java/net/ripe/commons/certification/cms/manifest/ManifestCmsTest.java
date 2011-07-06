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

import static net.ripe.commons.certification.x509cert.X509CertificateBuilderHelper.*;

import static org.junit.Assert.*;

import static org.easymock.EasyMock.*;

import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.util.Collections;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.manifest.ManifestCms.FileContentSpecification;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlBuilder;
import net.ripe.commons.certification.util.KeyPairFactoryTest;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationResult;
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
	private static final KeyPair MANIFEST_KEY_PAIR = KeyPairFactoryTest.SECOND_TEST_KEY_PAIR;
	private static final X500Principal MANIFEST_DN = new X500Principal("CN=manifest");

	// Manifest data
	private static byte[] FOO_CONTENTS = { 'a', 'b', 'c' };
	private static byte[] BAR_CONTENTS = { 'd', 'e', 'f' };
	private static byte[] FOO_HASH = ManifestCms.hashContents(FOO_CONTENTS);
	private static byte[] BAR_HASH = ManifestCms.hashContents(BAR_CONTENTS);

	private static final DateTime THIS_UPDATE_TIME = new DateTime(2008, 9, 1, 22, 43, 29, 0, DateTimeZone.UTC);
	private static final DateTime NEXT_UPDATE_TIME = new DateTime(2008, 9, 2, 6, 43, 29, 0, DateTimeZone.UTC);

	private CrlLocator crlLocator;
    private ManifestCms subject;
    private X509ResourceCertificate rootCertificate;

    public static ManifestCms getRootManifestCms() {
	    return getRootManifestBuilder().build(MANIFEST_KEY_PAIR.getPrivate());
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

    	subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, result);

    	verify(crlLocator);

    	assertEquals(Collections.emptyList(), result.getFailures(result.getCurrentLocation()));
    	assertFalse(result.hasFailures());
    }

    @Test
    public void shouldNotValidateWithInvalidCrl() {
    	IpResourceSet resources = rootCertificate.getResources();

    	CertificateRepositoryObjectValidationContext context = new CertificateRepositoryObjectValidationContext(ROOT_CERTIFICATE_LOCATION, rootCertificate, resources);
    	final ValidationResult result = new ValidationResult();
    	result.push(ROOT_SIA_MANIFEST_RSYNC_LOCATION);

    	expect(crlLocator.getCrl(ROOT_MANIFEST_CRL_LOCATION, context, result)).andAnswer(new IAnswer<X509Crl>() {
    	    @Override
            public X509Crl answer() throws Throwable {
    	        assertEquals(ROOT_MANIFEST_CRL_LOCATION.toString(), result.getCurrentLocation());
    	        result.isTrue(false, ValidationString.CRL_SIGNATURE_VALID);
    	        return null;
    	    }
    	});
    	replay(crlLocator);

    	subject.validate(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), context, crlLocator, result);

    	verify(crlLocator);

    	assertTrue(result.hasFailureForCurrentLocation());
    	assertEquals(ROOT_SIA_MANIFEST_RSYNC_LOCATION.toString(), result.getCurrentLocation());
    	assertTrue(result.hasFailureForLocation(ROOT_MANIFEST_CRL_LOCATION.toString()));
    	assertEquals(new ValidationCheck(false, ValidationString.CRL_SIGNATURE_VALID), result.getResult(ROOT_MANIFEST_CRL_LOCATION, ValidationString.CRL_SIGNATURE_VALID));
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

	@SuppressWarnings("deprecation")
    private static ManifestCmsBuilder getRootManifestBuilder() {
		ManifestCmsBuilder builder = new ManifestCmsBuilder();
		builder.withCertificate(getManifestEEResourceCertificateBuilder().build());
		builder.withManifestNumber(BigInteger.valueOf(68));
		builder.withThisUpdateTime(THIS_UPDATE_TIME).withNextUpdateTime(NEXT_UPDATE_TIME);
		builder.putFile("foo1", FOO_HASH);
		builder.putFile("BaR", BAR_HASH);
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
		builder.withResources(InheritedIpResourceSet.getInstance());
		builder.withValidityPeriod(new ValidityPeriod(THIS_UPDATE_TIME, NEXT_UPDATE_TIME));
		builder.withCrlDistributionPoints(ROOT_MANIFEST_CRL_LOCATION);
		return builder;
	}

}
