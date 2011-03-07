package net.ripe.commons.provisioning.cms;


import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.security.cert.X509Certificate;

import org.junit.Test;

public class ProvisioningCmsObjectTest {

    @Test
    public void shouldCompareOnlyTheContentForEquality() {
        X509Certificate certificate1 = createMock(X509Certificate.class);
        X509Certificate certificate2 = createMock(X509Certificate.class);

        byte[] encodedContent = new byte[] {'f', 'o', 'o'};

        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1);
        ProvisioningCmsObject cms2 = new ProvisioningCmsObject(encodedContent, certificate2);

        assertEquals(cms1, cms2);
    }

    @Test
    public void shouldUseOnlyTheContentForHashcode() {
        X509Certificate certificate1 = createMock(X509Certificate.class);
        X509Certificate certificate2 = createMock(X509Certificate.class);

        byte[] encodedContent = new byte[] {'f', 'o', 'o'};

        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1);
        ProvisioningCmsObject cms2 = new ProvisioningCmsObject(encodedContent, certificate2);

        assertEquals(cms1.hashCode(), cms2.hashCode());
    }
}
