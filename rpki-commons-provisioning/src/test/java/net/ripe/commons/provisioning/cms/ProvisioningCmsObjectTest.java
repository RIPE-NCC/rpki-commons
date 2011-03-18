package net.ripe.commons.provisioning.cms;


import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collections;

import org.junit.Test;

public class ProvisioningCmsObjectTest {


    @Test
    public void shouldImplementEquals() {
        X509Certificate certificate1 = createMock(X509Certificate.class);
        X509CRL crl = createMock(X509CRL.class);
        byte[] encodedContent = new byte[] {'f', 'o', 'o'};
        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1, Collections.<X509Certificate>emptySet(), crl);

        assertFalse(cms1.equals(null));
        assertEquals(cms1, cms1);
        assertFalse(cms1.equals("not-the-same-type"));
    }

    @Test
    public void shouldCompareOnlyTheContentForEquality() {
        X509Certificate certificate1 = createMock(X509Certificate.class);
        X509Certificate certificate2 = createMock(X509Certificate.class);
        X509CRL crl = createMock(X509CRL.class);

        byte[] encodedContent = new byte[] {'f', 'o', 'o'};

        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1, Collections.<X509Certificate>emptySet(), crl);
        ProvisioningCmsObject cms2 = new ProvisioningCmsObject(encodedContent, certificate2, Collections.<X509Certificate>emptySet(), crl);

        assertEquals(cms1, cms2);
    }

    @Test
    public void shouldUseOnlyTheContentForHashcode() {
        X509Certificate certificate1 = createMock(X509Certificate.class);
        X509Certificate certificate2 = createMock(X509Certificate.class);
        X509CRL crl = createMock(X509CRL.class);

        byte[] encodedContent = new byte[] {'f', 'o', 'o'};

        ProvisioningCmsObject cms1 = new ProvisioningCmsObject(encodedContent, certificate1, Collections.<X509Certificate>emptySet(), crl);
        ProvisioningCmsObject cms2 = new ProvisioningCmsObject(encodedContent, certificate2, Collections.<X509Certificate>emptySet(), crl);

        assertEquals(cms1.hashCode(), cms2.hashCode());
    }
}
