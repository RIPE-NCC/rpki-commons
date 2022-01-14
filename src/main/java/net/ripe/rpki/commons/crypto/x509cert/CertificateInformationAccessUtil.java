package net.ripe.rpki.commons.crypto.x509cert;

import java.net.URI;

public class CertificateInformationAccessUtil {

    public static URI extractPublicationDirectory(X509CertificateInformationAccessDescriptor[] informationAccessDescriptors) {
        for (X509CertificateInformationAccessDescriptor informationAccessDescriptor : informationAccessDescriptors) {
            if (X509CertificateInformationAccessDescriptor.ID_AD_CA_REPOSITORY
                    .equals(informationAccessDescriptor.getMethod()))
                return informationAccessDescriptor.getLocation();
        }
        return null;
    }
}
