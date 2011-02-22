package net.ripe.commons.certification.validation;

import static org.junit.Assert.*;

import java.net.URI;

import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.junit.Test;

import com.gargoylesoftware.base.testing.EqualsTester;


public class CertificateRepositoryObjectValidationContextTest {

	private static final IpResourceSet CHILD_RESOURCE_SET = IpResourceSet.parse("10.8.0.0/16");

	private static URI location = URI.create("rsync://host/path");
	private static X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
	private static URI childLocation = URI.create("rsync://host/path/child");

	private CertificateRepositoryObjectValidationContext subject = create();

	public static CertificateRepositoryObjectValidationContext create() {
	    return new CertificateRepositoryObjectValidationContext(location, certificate);
	}

	@Test
	public void shouldContainLocationAndCertificateAndResources() {
		assertSame(location, subject.getLocation());
		assertSame(certificate, subject.getCertificate());
		assertSame(certificate.getResources(), subject.getResources());
	}

	@Test
	public void shouldUpdateResourcesForChildCertificateWithoutInheritedResources() {
        X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(CHILD_RESOURCE_SET);
		CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);
		assertEquals(CHILD_RESOURCE_SET, childContext.getResources());
	}

	@Test
	public void shouldNotUpdateResourcesForChildCertificateWithInheritedResources() {
        X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(InheritedIpResourceSet.getInstance());
		CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);
		assertEquals(subject.getResources(), childContext.getResources());
	}

	@Test
	public void shouldUpdateLocationAndCertificateForChildCertificate() {
		X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(InheritedIpResourceSet.getInstance());
		CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);

		assertSame(childLocation, childContext.getLocation());
		assertSame(childCertificate, childContext.getCertificate());
	}

	@Test
	public void testEquals() {
	    CertificateRepositoryObjectValidationContext a = new CertificateRepositoryObjectValidationContext(location, certificate);
	    CertificateRepositoryObjectValidationContext b = new CertificateRepositoryObjectValidationContext(location, certificate);
	    CertificateRepositoryObjectValidationContext c = new CertificateRepositoryObjectValidationContext(URI.create("rsync://another/uri"), X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(InheritedIpResourceSet.getInstance()));
        CertificateRepositoryObjectValidationContext d = new CertificateRepositoryObjectValidationContext(location, certificate) {};
	    new EqualsTester(a, b, c, d);
	}
}
