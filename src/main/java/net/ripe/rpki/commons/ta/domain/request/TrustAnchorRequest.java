package net.ripe.rpki.commons.ta.domain.request;


import lombok.EqualsAndHashCode;
import lombok.Getter;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import org.joda.time.DateTimeUtils;

import java.io.Serializable;
import java.net.URI;
import java.util.List;

@Getter
@EqualsAndHashCode
public class TrustAnchorRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private final Long creationTimestamp;
    private final URI taCertificatePublicationUri;
    private final List<TaRequest> taRequests;
    private final X509CertificateInformationAccessDescriptor[] siaDescriptors;

    public TrustAnchorRequest(URI taCertificatePublicationUri, X509CertificateInformationAccessDescriptor[] siaDescriptors, List<TaRequest> taRequests) {
        this.creationTimestamp = DateTimeUtils.currentTimeMillis();
        this.taCertificatePublicationUri = taCertificatePublicationUri;
        this.taRequests = taRequests;
        this.siaDescriptors = siaDescriptors;
    }
}
