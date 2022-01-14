package net.ripe.rpki.commons.provisioning.serialization;

import net.ripe.ipresource.IpResourceSet;
import org.junit.Test;

import static org.junit.Assert.*;

public class IpResourceSetProvisioningConverterTest {
    private IpResourceSetProvisioningConverter subject = new IpResourceSetProvisioningConverter();

    @Test
    public void shouldStripASPrefix() {
        IpResourceSet asn = IpResourceSet.parse("AS3333");
        assertEquals("3333", subject.toString(asn));
        assertEquals(asn, subject.fromString(subject.toString(asn)));
    }

    @Test
    public void shouldSeparateResourcesWithComma() {
        IpResourceSet two = IpResourceSet.parse("127.0.0.0/8, 192.168.0.0/16");
        assertEquals("127.0.0.0/8,192.168.0.0/16", subject.toString(two));
        assertEquals(two, subject.fromString(subject.toString(two)));
    }
}
