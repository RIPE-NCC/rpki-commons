package net.ripe.commons.provisioning.cms;

import net.ripe.commons.provisioning.message.list.request.ResourceClassListQueryPayloadBuilder;

import static net.ripe.commons.provisioning.ProvisioningObjectMother.CRL;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR;
import static net.ripe.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT;
import static net.ripe.commons.provisioning.x509.ProvisioningIdentityCertificateBuilderTest.TEST_IDENTITY_CERT;

public abstract class ProvisioningCmsObjectBuilderMother {

    public static ProvisioningCmsObject createProvisioningCmsObject() {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        payloadBuilder.withRecipient("recipient");
        payloadBuilder.withSender("sender");
        String payloadXml = payloadBuilder.build();

        ProvisioningCmsObjectBuilder subject = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(TEST_CMS_CERT.getCertificate())
                .withCrl(CRL)
                .withCaCertificate(TEST_IDENTITY_CERT.getCertificate())
                .withPayloadContent(payloadXml);
        return subject.build(EE_KEYPAIR.getPrivate());
    }
}
