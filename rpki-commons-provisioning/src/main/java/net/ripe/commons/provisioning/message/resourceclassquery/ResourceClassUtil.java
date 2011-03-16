package net.ripe.commons.provisioning.message.resourceclassquery;

import net.ripe.commons.certification.x509cert.AbstractX509CertificateWrapperException;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.IpRange;
import org.bouncycastle.util.encoders.Base64Encoder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;

public class ResourceClassUtil {

    static IpRange[] toIpRange(String[] ipRanges) {
        int index = 0;
        IpRange[] ranges = new IpRange[ipRanges.length];

        for (String ip : ipRanges) {
            ranges[index++] = IpRange.parse(ip);
        }

        return ranges;
    }

    static boolean hasRsyncUri(URI[] uris) {
        boolean rsyncUriFound = false;

        if (uris == null) {
            return rsyncUriFound;
        }

        for (URI uri : uris) {
            if (uri.getScheme().toLowerCase().startsWith("rsync")) {
                rsyncUriFound = true;
                break;
            }
        }
        return rsyncUriFound;
    }

    static boolean hasRsyncUri(String[] uris) {
        boolean rsyncUriFound = false;

        if (uris == null) {
            return rsyncUriFound;
        }

        for (String uri : uris) {
            if (uri.startsWith("rsync:")) {
                rsyncUriFound = true;
                break;
            }
        }
        return rsyncUriFound;
    }

    static String encodeCertificate(X509ResourceCertificate certificate) {
        try {
            byte[] derEncoded = certificate.getEncoded();
            Base64Encoder encoder = new Base64Encoder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encoder.encode(derEncoded, 0, derEncoded.length, out);
            out.flush();
            return out.toString();
        } catch (IOException e) {
            throw new AbstractX509CertificateWrapperException("Can't encode SubjectPublicKeyInfo for certificate", e);
        }

    }
}
