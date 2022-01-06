package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.XStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;

public class AliasedNetRipeTypePermissionTest {
    private XStream xStream;
    private AliasedNetRipeTypePermission permission;

    @Before
    public void initialize() {
        this.xStream = new XStream();
        this.permission = new AliasedNetRipeTypePermission(xStream);
    }

    /**
     * Initially rejected but accepted after being aliased.
     */
    @Test
    public void shouldAcceptAliasedTypes() {
        Assert.assertFalse(this.permission.allows(SerializeMe.class));

        xStream.alias("serialize-me", SerializeMe.class);

        Assert.assertTrue(this.permission.allows(SerializeMe.class));
    }

    @Test
    public void shouldAcceptAliasedPackageMembers() {
        Assert.assertFalse(this.permission.allows(SerializeMe.class));

        xStream.aliasPackage("rpki-commons", "net.ripe.rpki.commons");

        Assert.assertTrue(this.permission.allows(SerializeMe.class));
    }

    /**
     * Reject a non-ripe type. If a non-ripe type needs to be accepted because of an default alias exists for it,
     * it should be allowed explicitly.
     */
    @Test
    public void shoudldRejectNonRipeTypes() {
        xStream.alias("non-ripe-type", ArrayList.class);

        Assert.assertFalse(this.permission.allows(ArrayList.class));
    }

    private static class SerializeMe {
    }
}
