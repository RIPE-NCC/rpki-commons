package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.XStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class AliasedTypePermissionTest {
    private XStream xStream;
    private AliasedTypePermission permission;

    @Before
    public void initialize() {
        this.xStream = new XStream();
        this.permission = new AliasedTypePermission(xStream);
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

    private static class SerializeMe {
    }
}
