package net.ripe.commons.provisioning.cms;

import org.bouncycastle.asn1.DEREncodable;
import org.junit.Test;


public class ProvisioningCmsObjectParserTest {


    @Test
    public void shouldParseValidObject() {
        ProvisioningCmsObject cmsObject = ProvisioningCmsObjectBuilderTest.createProvisioningCmsObject();
        ProvisioningCmsObjectParser parser = new ProvisioningCmsObjectParser(cmsObject.getEncoded()) {
            @Override
            protected void decodeContent(DEREncodable encoded) {
            }
        };
        parser.parseCms();
    }
}
