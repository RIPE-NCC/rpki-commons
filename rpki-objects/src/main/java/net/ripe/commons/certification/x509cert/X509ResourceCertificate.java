package net.ripe.commons.certification.x509cert;

import net.ripe.commons.certification.rfc3779.ResourceExtensionEncoder;
import net.ripe.commons.certification.rfc3779.ResourceExtensionParser;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;
import org.apache.commons.lang.Validate;

import java.security.cert.X509Certificate;

/**
 * Wraps a X509 certificate containing RFC3779 resource extensions.
 */
public class X509ResourceCertificate extends X509PlainCertificate {

    private static final long serialVersionUID = 2L;

    private IpResourceSet resources;


    protected X509ResourceCertificate(X509Certificate certificate) {
        super(certificate);
        parseResourceExtensions();
    }

    private void parseResourceExtensions() {
        ResourceExtensionParser parser = new ResourceExtensionParser();
        IpResourceSet result = new IpResourceSet();
        boolean ipInherited = false;
        boolean asInherited = false;
        byte[] ipAddressBlocksExtension = getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS);
        if (ipAddressBlocksExtension != null) {
            IpResourceSet ipResources = parser.parseIpAddressBlocks(ipAddressBlocksExtension);
            if (ipResources == null) {
                ipInherited = true;
            } else {
                result.addAll(ipResources);
            }
        }
        byte[] asnExtension = getCertificate().getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS);
        if (asnExtension != null) {
            IpResourceSet asResources = parser.parseAsIdentifiers(asnExtension);
            if (asResources == null) {
                asInherited = true;
            } else {
                result.addAll(asResources);
            }
        }
        Validate.isTrue(ipInherited == asInherited, "partial inheritance not supported");
        resources = ipInherited && asInherited ? InheritedIpResourceSet.getInstance() : result;
        Validate.isTrue(!resources.isEmpty(), "empty resource set");
    }

    public IpResourceSet getResources() {
        return resources;
    }

    public boolean isResourceSetInherited() {
        return resources instanceof InheritedIpResourceSet;
    }


    public static X509ResourceCertificate parseDerEncoded(byte[] encoded) {
        X509CertificateParser<X509ResourceCertificate> parser = X509CertificateParser.forResourceCertificate();
        parser.parse("certificate", encoded);
        return parser.getCertificate();
    }
}
