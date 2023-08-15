package net.ripe.rpki.commons.ta.domain.request;


import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;

import java.io.Serializable;
import java.net.URI;
import java.util.List;

public class TrustAnchorRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Long creationTimestamp;
    private final URI taCertificatePublicationUri;
    private final List<TaRequest> taRequests;
    private final X509CertificateInformationAccessDescriptor[] siaDescriptors;

    public TrustAnchorRequest(URI taCertificatePublicationUri, X509CertificateInformationAccessDescriptor[] siaDescriptors, List<TaRequest> taRequests) {
        this.creationTimestamp = System.currentTimeMillis();
        this.taCertificatePublicationUri = taCertificatePublicationUri;
        this.taRequests = taRequests;
        this.siaDescriptors = siaDescriptors;
    }

    public Long getCreationTimestamp() {
        return creationTimestamp;
    }

    public URI getTaCertificatePublicationUri() {
        return taCertificatePublicationUri;
    }

    public List<TaRequest> getTaRequests() {
        return taRequests;
    }

    public X509CertificateInformationAccessDescriptor[] getSiaDescriptors() {
        return siaDescriptors;
    }
}
