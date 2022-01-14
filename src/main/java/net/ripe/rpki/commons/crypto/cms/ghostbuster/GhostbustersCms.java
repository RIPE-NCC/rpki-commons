package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateValidator;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import java.net.URI;

/**
 * A ghostbusters RPKI object as defined in <a href="https://tools.ietf.org/html/rfc6493">RFC6493</a>.
 */
public class GhostbustersCms extends RpkiSignedObject {

    public static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.35");
    private String vCardContent;

    GhostbustersCms(RpkiSignedObjectInfo cmsObjectData, String vCardContent) {
        super(cmsObjectData);
        this.vCardContent = vCardContent;
    }

    @Override
    protected void validateWithCrl(String location, CertificateRepositoryObjectValidationContext context, ValidationOptions options, ValidationResult result, X509Crl crl) {
        X509ResourceCertificateValidator validator = ResourceValidatorFactory.getX509ResourceCertificateStrictValidator(context, options, result, crl);
        validator.validate(location, getCertificate());
    }

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }

    public String getVCardContent() {
        return vCardContent;
    }

    @Deprecated
    public String getvCard() {
        return vCardContent;
    }
}
