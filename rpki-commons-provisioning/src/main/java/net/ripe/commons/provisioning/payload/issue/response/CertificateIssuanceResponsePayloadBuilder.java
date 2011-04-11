package net.ripe.commons.provisioning.payload.issue.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.payload.common.AbstractPayloadBuilder;

import org.apache.commons.lang.Validate;


/**
 * Builder for 'Certificate Issuance Response'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2</a>
 */
public class CertificateIssuanceResponsePayloadBuilder extends AbstractPayloadBuilder {

    private static final XStreamXmlSerializer<CertificateIssuanceResponsePayload> SERIALIZER = new CertificateIssuanceResponsePayloadSerializerBuilder().build();

    private CertificateIssuanceResponseClassElement classElement;

    public CertificateIssuanceResponsePayloadBuilder withClassElement(CertificateIssuanceResponseClassElement classElement) {
        this.classElement = classElement;
        return this;
    }

    @Override
    protected final void onValidateFields() {
        Validate.notNull(classElement, "Need one ClassElement");
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {
        CertificateIssuanceResponsePayload wrapper = new CertificateIssuanceResponsePayload(sender, recipient, classElement);
         return SERIALIZER.serialize(wrapper);
    }

}
