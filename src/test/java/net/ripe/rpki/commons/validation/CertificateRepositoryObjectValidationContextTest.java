package net.ripe.rpki.commons.validation;

import com.google.common.testing.EqualsTester;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.util.EnumSet;

import static org.junit.Assert.*;


public class CertificateRepositoryObjectValidationContextTest {

    private static final IpResourceSet CHILD_RESOURCE_SET = IpResourceSet.parse("10.8.0.0/16");

    private static URI location = URI.create("rsync://host/path");
    private static X509ResourceCertificate certificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();
    private static URI childLocation = URI.create("rsync://host/path/child");

    private CertificateRepositoryObjectValidationContext subject = create();

    private X509ResourceCertificate certificateWithInheritedResources;

    public static CertificateRepositoryObjectValidationContext create() {
        return new CertificateRepositoryObjectValidationContext(location, certificate);
    }

    @Before
    public void setUp() {
        certificateWithInheritedResources = X509ResourceCertificateTest.
                createSelfSignedCaResourceCertificateBuilder().
                withInheritedResourceTypes(EnumSet.allOf(IpResourceType.class))
                .withResources(new IpResourceSet()).
                        build();
    }

    @Test
    public void shouldContainLocationAndCertificateAndResources() {
        assertSame(location, subject.getLocation());
        assertSame(certificate, subject.getCertificate());
        assertEquals(certificate.getResources(), subject.getResources());
    }

    @Test
    public void shouldUpdateResourcesForChildCertificateWithoutInheritedResources() {
        X509ResourceCertificate childCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(CHILD_RESOURCE_SET);
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, childCertificate);
        assertEquals(CHILD_RESOURCE_SET, childContext.getResources());
    }

    @Test
    public void shouldNotUpdateResourcesForChildCertificateWithInheritedResources() {
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, certificateWithInheritedResources);
        assertEquals(subject.getResources(), childContext.getResources());
    }

    @Test
    public void shouldUpdateLocationAndCertificateForChildCertificate() {
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, certificateWithInheritedResources);

        assertSame(childLocation, childContext.getLocation());
        assertSame(certificateWithInheritedResources, childContext.getCertificate());
    }

    @Test
    public void shouldUpdateSubjectChainForChildCertificate() {
        CertificateRepositoryObjectValidationContext childContext = subject.createChildContext(childLocation, certificateWithInheritedResources);

        assertEquals(subject.getSubjectChain().size() + 1, childContext.getSubjectChain().size());
        assertEquals(certificateWithInheritedResources.getSubject().getName(), childContext.getSubjectChain().get(childContext.getSubjectChain().size() - 1));
    }

    @Test
    public void testEquals() {
        // Two equal objects
        CertificateRepositoryObjectValidationContext a = new CertificateRepositoryObjectValidationContext(location, certificate);
        CertificateRepositoryObjectValidationContext b = new CertificateRepositoryObjectValidationContext(location, certificate);
        // A different one
        CertificateRepositoryObjectValidationContext c = new CertificateRepositoryObjectValidationContext(URI.create("rsync://another/uri"), certificateWithInheritedResources);
        // And one of a different type.
        CertificateRepositoryObjectValidationContext d = new CertificateRepositoryObjectValidationContext(location, certificate) {
        };

        new EqualsTester()
                .addEqualityGroup(a, b)
                .addEqualityGroup(c)
                .addEqualityGroup(d)
                .testEquals();
    }
}
