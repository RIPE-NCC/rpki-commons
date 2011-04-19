package net.ripe.commons.certification.x509cert;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.ripe.utils.support.ValueObjectSupport;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

public class X509CertificateInformationAccessDescriptor extends ValueObjectSupport {

    public static final DERObjectIdentifier ID_CA_CA_ISSUERS = AccessDescription.id_ad_caIssuers;

    public static final DERObjectIdentifier ID_AD_CA_REPOSITORY = new DERObjectIdentifier(X509ObjectIdentifiers.id_ad + ".5");

    public static final DERObjectIdentifier ID_AD_SIGNED_OBJECT_REPOSITORY = new DERObjectIdentifier(X509ObjectIdentifiers.id_ad + ".9");

    public static final DERObjectIdentifier ID_AD_SIGNED_OBJECT = new DERObjectIdentifier(X509ObjectIdentifiers.id_ad + ".11");

    public static final DERObjectIdentifier ID_AD_RPKI_MANIFEST = new DERObjectIdentifier(X509ObjectIdentifiers.id_ad + ".10");

    private static final long serialVersionUID = 1L;

    private String method;
    private URI location;

    private static final Map<DERObjectIdentifier, String> METHOD_STRING_TABLE;

    static {
        Map<DERObjectIdentifier, String> map = new HashMap<DERObjectIdentifier, String>();
        map.put(ID_CA_CA_ISSUERS, "ca issuer");
        map.put(ID_AD_CA_REPOSITORY, "ca repository");
        map.put(ID_AD_SIGNED_OBJECT_REPOSITORY, "signed object repository");
        map.put(ID_AD_SIGNED_OBJECT, "signed object");
        map.put(ID_AD_RPKI_MANIFEST, "manifest");
        METHOD_STRING_TABLE = Collections.unmodifiableMap(map);
    }

    public X509CertificateInformationAccessDescriptor(AccessDescription accessDescription) {
        try {
            Validate.isTrue(accessDescription.getAccessLocation().getTagNo() == GeneralName.uniformResourceIdentifier, "access location is not an URI");
            this.method = accessDescription.getAccessMethod().getId();
            this.location = new URI(accessDescription.getAccessLocation().getName().toString());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public X509CertificateInformationAccessDescriptor(DERObjectIdentifier method, URI location) {
        super();
        this.method = method.getId();
        this.location = location;
    }

    public DERObjectIdentifier getMethod() {
        return new DERObjectIdentifier(method);
    }

    public URI getLocation() {
        return location;
    }

    public static AccessDescription[] convertAccessDescriptors(X509CertificateInformationAccessDescriptor... descriptors) {
        Validate.noNullElements(descriptors);
        AccessDescription[] result = new AccessDescription[descriptors.length];
        for (int i = 0; i < descriptors.length; ++i) {
            result[i] = descriptors[i].toAccessDescription();
        }
        return result;
    }

    private AccessDescription toAccessDescription() {
        return new AccessDescription(getMethod(), new GeneralName(GeneralName.uniformResourceIdentifier, location.toString()));
    }

    public static X509CertificateInformationAccessDescriptor[] convertAccessDescriptors(AccessDescription... accessDescriptions) {
        X509CertificateInformationAccessDescriptor[] result = new X509CertificateInformationAccessDescriptor[accessDescriptions.length];
        for (int i = 0; i < result.length; ++i) {
            result[i] = new X509CertificateInformationAccessDescriptor(accessDescriptions[i]);
        }
        return result;
    }

    public static String methodToString(DERObjectIdentifier method) {
        Validate.notNull(method);
        String result = METHOD_STRING_TABLE.get(method);
        return result == null ? method.toString() : result;
    }

    public static DERObjectIdentifier stringToMethod(String method) {
        Validate.notNull(method);
        for (Map.Entry<DERObjectIdentifier, String> entry: METHOD_STRING_TABLE.entrySet()) {
            if (entry.getValue().equals(method)) {
                return entry.getKey();
            }
        }
        return new DERObjectIdentifier(method);
    }
}
