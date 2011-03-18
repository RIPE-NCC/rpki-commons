package net.ripe.commons.provisioning.message.revocation;

import net.ripe.certification.client.xml.XStreamXmlSerializer;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.provisioning.message.common.CommonCmsBuilder;
import org.apache.commons.lang.Validate;

public class RevocationCmsBuilder extends CommonCmsBuilder {
    private static final XStreamXmlSerializer<RevocationPayloadWrapper> SERIALIZER = new RevocationPayloadWrapperSerializerBuilder().build();

    private String className;
    private X509ResourceCertificate certificate;

    public void withClassName(String className) {
        this.className = className;
    }

    public void withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
    }

    @Override
    protected void onValidateFields() {
        Validate.notNull(className, "Classname is required");
        Validate.notNull(certificate, "Certificate is required");
    }

    @Override
    protected String serializePayloadWrapper(String sender, String recipient) {

        byte[] subjectKeyIdentifier = certificate.getSubjectKeyIdentifier();

        RevocationPayload payload = new RevocationPayload(className, subjectKeyIdentifier);

        RevocationPayloadWrapper wrapper = new RevocationPayloadWrapper(sender, recipient, payload);

        return SERIALIZER.serialize(wrapper);
    }
}
