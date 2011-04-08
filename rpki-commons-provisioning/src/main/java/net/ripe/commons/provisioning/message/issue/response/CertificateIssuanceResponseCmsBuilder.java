package net.ripe.commons.provisioning.message.issue.response;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.provisioning.cms.ProvisioningCmsObjectBuilder;

import org.apache.commons.lang.Validate;


/**
 * Builder for 'Certificate Issuance Response'<br >
 * See: <a href="http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2">http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.4.2</a>
 */
public class CertificateIssuanceResponseCmsBuilder extends ProvisioningCmsObjectBuilder {

    private static final XStreamXmlSerializer<CertificateIssuanceResponsePayload> SERIALIZER = new CertificateIssuanceResponsePayloadSerializerBuilder()
            .build();

    private CertificateIssuanceResponseClassElement classElement;

    public CertificateIssuanceResponseCmsBuilder withClassElement(CertificateIssuanceResponseClassElement classElement) {
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
