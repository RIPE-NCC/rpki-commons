package net.ripe.rpki.commons.ta.domain.request;


import lombok.EqualsAndHashCode;
import lombok.Getter;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;

import javax.security.auth.x500.X500Principal;
import java.io.Serializable;
import java.security.PublicKey;

@Getter
@EqualsAndHashCode
public class ResourceCertificateRequestData implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String resourceClassName;
    private final X500Principal subjectDN;
    private final X509CertificateInformationAccessDescriptor[] subjectInformationAccess;
    private final IpResourceSet ipResourceSet;
    private final byte[] encodedSubjectPublicKey;

    public static ResourceCertificateRequestData forTASigningRequest(
            String resourceClassName,
            X500Principal subjectDN,
            byte[] encodedSubjectPublicKey,
            X509CertificateInformationAccessDescriptor[] subjectInformationAccess
    ) {
        return new ResourceCertificateRequestData(resourceClassName, subjectDN, encodedSubjectPublicKey, subjectInformationAccess, null);
    }

    public static ResourceCertificateRequestData forUpstreamCARequest(
            String resourceClassName,
            X500Principal subjectDN,
            PublicKey subjectPublicKey,
            X509CertificateInformationAccessDescriptor[] subjectInformationAccess,
            IpResourceSet ipResourceSet
    ) {
        return new ResourceCertificateRequestData(resourceClassName, subjectDN, subjectPublicKey.getEncoded(), subjectInformationAccess, ipResourceSet);
    }

    public ResourceCertificateRequestData(String resourceClassName, X500Principal subjectDN, byte[] encodedSubjectPublicKey,
                                          X509CertificateInformationAccessDescriptor[] subjectInformationAccess, IpResourceSet ipResourceSet) {
        this.resourceClassName = resourceClassName;
        this.subjectDN = subjectDN;
        this.encodedSubjectPublicKey = encodedSubjectPublicKey;
        this.subjectInformationAccess = subjectInformationAccess;
        this.ipResourceSet = ipResourceSet;
    }
}
