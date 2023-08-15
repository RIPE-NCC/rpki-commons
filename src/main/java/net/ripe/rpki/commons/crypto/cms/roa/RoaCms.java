package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.util.Collections;
import java.util.List;

public class RoaCms extends RpkiSignedObject implements Roa {

    public static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.24");

    private static final long serialVersionUID = 1L;

    private final Asn asn;

    private final List<RoaPrefix> prefixes;

    protected RoaCms(RpkiSignedObjectInfo cmsObjectInfo, Asn asn, List<RoaPrefix> prefixes) {
        super(cmsObjectInfo);
        this.asn = asn;
        this.prefixes = prefixes;
    }

    @Override
    public Asn getAsn() {
        return asn;
    }

    public IpResourceSet getResources() {
        return getCertificate().getResources();
    }

    @Override
    public List<RoaPrefix> getPrefixes() {
        return Collections.unmodifiableList(prefixes);
    }

    /**
     * @deprecated use {@link RoaCmsParser#parse(ValidationResult, byte[]) RoaCmsParser} or
     * {@link net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory#createCertificateRepositoryObject(byte[], ValidationResult) CertificateRepositoryObjectParser}
     */
    @Deprecated
    public static RoaCms parseDerEncoded(byte[] encoded) {
        RoaCmsParser parser = new RoaCmsParser();
        parser.parse(ValidationResult.withLocation("unknown.roa"), encoded);
        return parser.getRoaCms();
    }
}
