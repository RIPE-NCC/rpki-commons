package net.ripe.rpki.commons.provisioning.identity;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificate;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningIdentityCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.xml.DomXmlSerializer;
import net.ripe.rpki.commons.xml.DomXmlSerializerException;
import org.w3c.dom.Document;

import java.util.Base64;
import java.util.Optional;


public abstract class IdentitySerializer<T> extends DomXmlSerializer<T> {

    public static final String XMLNS = "http://www.hactrn.net/uris/rpki/rpki-setup/";

    public IdentitySerializer() {
        super(XMLNS);
    }

    protected Optional<String> getBpkiElementContent(final Document doc, final String nodeName) {
        return getElement(doc, nodeName).map(e -> e.getTextContent().replaceAll("\\s+", ""));
    }

    protected ProvisioningIdentityCertificate getProvisioningIdentityCertificate(final String bpkiTa) {
        final ProvisioningIdentityCertificateParser parser = new ProvisioningIdentityCertificateParser();
        parser.parse(ValidationResult.withLocation("unknown.cer"), Base64.getMimeDecoder().decode(bpkiTa));
        return parser.getCertificate();
    }
}
