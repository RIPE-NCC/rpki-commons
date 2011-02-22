package net.ripe.commons.certification.cms.roa;

import net.ripe.commons.certification.cms.CmsObject;
import net.ripe.commons.certification.cms.CmsObjectInfo;
import net.ripe.commons.certification.validation.objectvalidators.X509ResourceCertificateValidator;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceSet;

import java.net.URI;
import java.util.Collections;
import java.util.List;

public class RoaCms extends CmsObject<X509ResourceCertificate> implements Roa {

    public static final String CONTENT_TYPE = "1.2.840.113549.1.9.16.1.24";

    private static final long serialVersionUID = 1L;

    private Asn asn;

    private List<RoaPrefix> prefixes;

    protected RoaCms(CmsObjectInfo cmsObjectInfo, Asn asn, List<RoaPrefix> prefixes) {
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

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }

    public static RoaCms parseDerEncoded(byte[] encoded) {
        RoaCmsParser parser = new RoaCmsParser();
        parser.parse("<unknown>", encoded);
        return parser.getRoaCms();
    }

    @Override
    public void validate(String location, X509ResourceCertificateValidator validator) {
        RoaCmsParser parser = new RoaCmsParser(validator.getValidationResult());
        parser.parse(location, getEncoded());
        if (parser.getValidationResult().hasFailures()) {
            return;
        }
        validator.validate(location, getCertificate());
    }
}
