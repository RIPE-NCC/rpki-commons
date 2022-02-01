package net.ripe.rpki.commons.xml;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.util.VersionedId;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Period;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.sql.Timestamp;
import java.util.Objects;
import java.util.SortedSet;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assert.assertEquals;


public class XStreamXmlSerializerBuilderTest {


    private static final boolean NOT_STRICT = false;

    @Test
    public void shouldCreateSerializer() {
        XStreamXmlSerializerBuilder<String> builder = new XStreamXmlSerializerBuilder<>(String.class, NOT_STRICT);
        XStreamXmlSerializer<String> serializer = builder.build();

        String serializedData = serializer.serialize("foo");
        Assert.assertEquals("<string>foo</string>", serializedData);
    }

    @Test
    public void shouldAliasCommonsPackage() {
        XStreamXmlSerializerBuilder<ValidityPeriod> builder = new XStreamXmlSerializerBuilder<>(ValidityPeriod.class, NOT_STRICT);
        XStreamXmlSerializer<ValidityPeriod> serializer = builder.build();

        String serializedData = serializer.serialize(new ValidityPeriod());
        Assert.assertEquals("<ValidityPeriod/>", serializedData);
    }

    @Test
    public void shouldAliasIpResourceAndUseConverter() {
        XStreamXmlSerializerBuilder<IpResource> builder = new XStreamXmlSerializerBuilder<>(IpResource.class, NOT_STRICT);
        XStreamXmlSerializer<IpResource> serializer = builder.build();
        IpResource ipResource = IpResource.parse("10/8");

        String serializedData = serializer.serialize(ipResource);
        Assert.assertEquals("<resource>10.0.0.0/8</resource>", serializedData);
        assertEquals(ipResource, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasIpResourceSetAndUseConverter() {
        XStreamXmlSerializerBuilder<IpResourceSet> builder = new XStreamXmlSerializerBuilder<>(IpResourceSet.class, NOT_STRICT);
        XStreamXmlSerializer<IpResourceSet> serializer = builder.build();
        IpResourceSet ipResourceSet = IpResourceSet.parse("10/8");

        String serializedData = serializer.serialize(ipResourceSet);
        Assert.assertEquals("<resource-set>10.0.0.0/8</resource-set>", serializedData);
        assertEquals(ipResourceSet, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasDateTimeAndUseConverter() {
        XStreamXmlSerializerBuilder<DateTime> builder = new XStreamXmlSerializerBuilder<>(DateTime.class, NOT_STRICT);
        XStreamXmlSerializer<DateTime> serializer = builder.build();
        DateTime dateTime = new DateTime(2011, 1, 31, 13, 59, 59, 0, DateTimeZone.UTC);

        String serializedData = serializer.serialize(dateTime);
        Assert.assertEquals("<datetime>2011-01-31T13:59:59Z</datetime>", serializedData);
        assertEquals(dateTime, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertDateTimeFromTimeStamp() {
        XStreamXmlSerializerBuilder<Timestamp> builder = new XStreamXmlSerializerBuilder<>(Timestamp.class, NOT_STRICT);
        XStreamXmlSerializer<Timestamp> serializer = builder.build();
        Timestamp timestamp = new Timestamp(new DateTime(2011, 1, 31, 13, 59, 59, 0, DateTimeZone.UTC).getMillis());

        String serializedData = serializer.serialize(timestamp);
        Assert.assertEquals("<sql-timestamp>2011-01-31T13:59:59.000Z</sql-timestamp>", serializedData);
        assertEquals(timestamp, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertDateTimeFromReadablePeriod() {
        XStreamXmlSerializerBuilder<Period> builder = new XStreamXmlSerializerBuilder<>(Period.class, NOT_STRICT);
        XStreamXmlSerializer<Period> serializer = builder.build();
        DateTime now = UTC.dateTime();
        Period period = new Period(now, now.plusHours(1));

        String serializedData = serializer.serialize(period);
        Assert.assertEquals("<org.joda.time.Period>PT1H</org.joda.time.Period>", serializedData);
        assertEquals(period, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasPrincipalAndUseConverter() {
        XStreamXmlSerializerBuilder<X500Principal> builder = new XStreamXmlSerializerBuilder<>(X500Principal.class, NOT_STRICT);
        XStreamXmlSerializer<X500Principal> serializer = builder.build();
        X500Principal principal = new X500Principal("CN=nl.bluelight");

        String serializedData = serializer.serialize(principal);
        Assert.assertEquals("<principal>CN=nl.bluelight</principal>", serializedData);
        assertEquals(principal, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertVersionedId() {
        XStreamXmlSerializerBuilder<VersionedId> builder = new XStreamXmlSerializerBuilder<>(VersionedId.class, NOT_STRICT);
        XStreamXmlSerializer<VersionedId> serializer = builder.build();
        VersionedId versionedId = new VersionedId(1L, 2L);

        String serializedData = serializer.serialize(versionedId);
        Assert.assertEquals("<versionedId>1:2</versionedId>", serializedData);
        assertEquals(versionedId, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertX509ResourceCertificate() {
        XStreamXmlSerializerBuilder<X509ResourceCertificate> builder = new XStreamXmlSerializerBuilder<>(X509ResourceCertificate.class, NOT_STRICT);
        XStreamXmlSerializer<X509ResourceCertificate> serializer = builder.build();
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();

        String serializedData = serializer.serialize(resourceCertificate);
        Assert.assertTrue(Pattern.matches("<X509ResourceCertificate>\\s*<encoded>[^<]+</encoded>\\s*</X509ResourceCertificate>", serializedData));
        assertEquals(resourceCertificate, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertManifestCms() {
        XStreamXmlSerializerBuilder<ManifestCms> builder = new XStreamXmlSerializerBuilder<>(ManifestCms.class, NOT_STRICT);
        XStreamXmlSerializer<ManifestCms> serializer = builder.build();
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

        String serializedData = serializer.serialize(manifestCms);
        Assert.assertTrue(Pattern.matches("<ManifestCms>\\s*<encoded>[^<]+</encoded>\\s*</ManifestCms>", serializedData));
        assertEquals(manifestCms, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertRoaCms() {
        XStreamXmlSerializerBuilder<RoaCms> builder = new XStreamXmlSerializerBuilder<>(RoaCms.class, NOT_STRICT);
        XStreamXmlSerializer<RoaCms> serializer = builder.build();
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        String serializedData = serializer.serialize(roaCms);
        Assert.assertTrue(Pattern.matches("<RoaCms>\\s*<encoded>[^<]+</encoded>\\s*</RoaCms>", serializedData));
        assertEquals(roaCms, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldIgnoreUnknownElements() {
        XStreamXmlSerializerBuilder<String> builder = new XStreamXmlSerializerBuilder<>(String.class, NOT_STRICT);
        XStreamXmlSerializer<String> serializer = builder.build();

        String deserializedData = serializer.deserialize("<string>sample string</string><foo/>");
        Assert.assertEquals("sample string", deserializedData);
    }

    @Test
    public void shouldAliasPackage() {
        XStreamXmlSerializerBuilder<SerializeMe> builder = new XStreamXmlSerializerBuilder<>(SerializeMe.class, NOT_STRICT);
        builder.withAliasPackage("test-alias", SerializeMe.class.getPackage().getName());
        XStreamXmlSerializer<SerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new SerializeMe());
        Assert.assertEquals("<test-alias.XStreamXmlSerializerBuilderTest_-SerializeMe/>", serializedData);
    }

    @Test
    public void shouldDeserializeOwnType() {
        XStreamXmlSerializerBuilder<SerializeMe> builder = new XStreamXmlSerializerBuilder<>(SerializeMe.class, NOT_STRICT);
        XStreamXmlSerializer<SerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new SerializeMe());
        serializer.deserialize(serializedData);
        Assert.assertEquals("<net.ripe.rpki.commons.xml.XStreamXmlSerializerBuilderTest_-SerializeMe/>", serializedData);
    }

    @Test(expected = ForbiddenClassException.class)
    public void shouldNotDeserializeUnknownType() {
        XStreamXmlSerializerBuilder<SerializeMe> builder = new XStreamXmlSerializerBuilder<>(SerializeMe.class, NOT_STRICT);
        XStreamXmlSerializer<SerializeMe> deserializer = builder.build();

        XStreamXmlSerializer<OtherSerializeMe> otherSerializer = new XStreamXmlSerializerBuilder<>(OtherSerializeMe.class, NOT_STRICT).build();

        String serializedData = otherSerializer.serialize(new OtherSerializeMe(new SerializeMe()));
        // Should throw, input type is unknown:
        deserializer.deserialize(serializedData);
    }

    @Test
    public void shouldAllowExplicitlyAllowedType() {
        XStreamXmlSerializerBuilder<OtherSerializeMe> builder = new XStreamXmlSerializerBuilder<>(OtherSerializeMe.class, NOT_STRICT);
        builder.withAllowedType(SerializeMe.class);
        XStreamXmlSerializer<OtherSerializeMe> serializer = builder.build();

        final OtherSerializeMe input = new OtherSerializeMe(new SerializeMe());

        String serializedData = serializer.serialize(input);
        final OtherSerializeMe output = serializer.deserialize(serializedData);

        Assert.assertEquals(input.canBeAnything, output.canBeAnything);
    }

    @Test
    public void shouldAllowArrayOfExplicitlyAllowedType() {
        XStreamXmlSerializerBuilder<OtherSerializeMe> builder = new XStreamXmlSerializerBuilder<>(OtherSerializeMe.class, NOT_STRICT);
        builder.withAllowedType(SerializeMe.class);
        builder.withAllowedType(SerializeMe[].class);
        builder.withAllowedType(OtherSerializeMe.class);
        XStreamXmlSerializer<OtherSerializeMe> serializer = builder.build();

        final OtherSerializeMe input = new OtherSerializeMe(new SerializeMe[]{
                new SerializeMe(),
                new SerializeMe()
        });

        String serializedData = serializer.serialize(input);
        final OtherSerializeMe output = serializer.deserialize(serializedData);

        Assert.assertArrayEquals((Object[])input.canBeAnything, (Object[])output.canBeAnything);
    }

    @Test
    public void shouldSerializeHierarchy() {
        XStreamXmlSerializer<SerializeMeInterface> serializer = new XStreamXmlSerializerBuilder<>(SerializeMeInterface.class, NOT_STRICT).build();

        String serializedData = serializer.serialize(new SerializeMe());
        final SerializeMeInterface output = serializer.deserialize(serializedData);

        Assert.assertEquals(new SerializeMe(), output);
    }

    @Test
    public void shouldSerializeAllowedHierarchy() {
        XStreamXmlSerializerBuilder<WithSerializeMeInterfaceField> builder = new XStreamXmlSerializerBuilder<>(WithSerializeMeInterfaceField.class, NOT_STRICT);
        builder.withAllowedTypeHierarchy(SerializeMeInterface.class);
        XStreamXmlSerializer<WithSerializeMeInterfaceField> serializer = builder.build();

        WithSerializeMeInterfaceField input = new WithSerializeMeInterfaceField(new SerializeMe());

        String serializedData = serializer.serialize(input);
        final WithSerializeMeInterfaceField output = serializer.deserialize(serializedData);

        Assert.assertEquals(input, output);
    }

    @Test
    public void shouldAllowAliasedConcreteTypeInObjectField() {
        XStreamXmlSerializerBuilder<OtherSerializeMe> builder = new XStreamXmlSerializerBuilder<>(OtherSerializeMe.class, NOT_STRICT);
        builder.withAliasType("serialize-me", SerializeMe.class);
        XStreamXmlSerializer<OtherSerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new OtherSerializeMe(new SerializeMe()));
        Assert.assertTrue(serializedData.contains("serialize-me"));
        serializer.deserialize(serializedData);
    }

    @Test
    public void shouldAllowConcreteTypeFromAliasedPackageInObjectField() {
        XStreamXmlSerializerBuilder<OtherSerializeMe> builder = new XStreamXmlSerializerBuilder<>(OtherSerializeMe.class, NOT_STRICT);
        builder.withAliasPackage("rpki-commons-xml", "net.ripe.rpki.commons.xml");
        XStreamXmlSerializer<OtherSerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new OtherSerializeMe(new SerializeMe()));
        Assert.assertTrue(serializedData.contains("rpki-commons-xml"));
        serializer.deserialize(serializedData);
    }

    @Test
    public void shouldNotDeserializeUnknownTypeInObjectField() throws Throwable {
        // Similar to above but without the alias
        XStreamXmlSerializerBuilder<OtherSerializeMe> builder = new XStreamXmlSerializerBuilder<>(OtherSerializeMe.class, NOT_STRICT);
        XStreamXmlSerializer<OtherSerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new OtherSerializeMe(new SerializeMe()));
        // Should throw, not an instance of an allowed or aliased type
        assertThatThrownBy(() -> serializer.deserialize(serializedData))
                .isInstanceOf(ForbiddenClassException.class);
    }

    @Ignore("TreeSet constructor fails on JDK 17")
    @Test
    public void shouldNotPopCalculatorApp() {
        // Exploit example from https://www.baeldung.com/java-xstream-remote-code-execution
        final String potentialRceXML = "<sorted-set>\n" +
                "    <string>foo</string>\n" +
                "    <dynamic-proxy>\n" +
                "        <interface>java.lang.Comparable</interface>\n" +
                "        <handler class=\"java.beans.EventHandler\">\n" +
                "            <target class=\"java.lang.ProcessBuilder\">\n" +
                "                <command>\n" +
                "                    <string>open</string>\n" +
                "                    <string>/Applications/Calculator.app</string>\n" +
                "                </command>\n" +
                "            </target>\n" +
                "            <action>start</action>\n" +
                "        </handler>\n" +
                "    </dynamic-proxy>\n" +
                "</sorted-set>";

        XStreamXmlSerializer<SerializeMe> serializer = new XStreamXmlSerializerBuilder<>(SerializeMe.class, NOT_STRICT)
            .withAllowedTypeHierarchy(SortedSet.class)
            .withAllowedTypeHierarchy(String.class)
            .build();

        assertThatThrownBy(() -> serializer.deserialize(potentialRceXML))
                .isInstanceOf(ForbiddenClassException.class);
    }

    private interface SerializeMeInterface {
    }

    private static class SerializeMe implements SerializeMeInterface {
        /** Needed for Assert.assertArrayEquals. */
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            return !(o == null || getClass() != o.getClass());
        }

        @Override
        public int hashCode() {
            return 1;
        }
    }

    private static class OtherSerializeMe implements SerializeMeInterface {
        Object canBeAnything;

        public OtherSerializeMe(final Object canBeAnything) {
            this.canBeAnything = canBeAnything;
        }
    }

    private static class WithSerializeMeInterfaceField {
        SerializeMeInterface inner;

        public WithSerializeMeInterfaceField(final SerializeMeInterface inner) { this.inner = inner; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            WithSerializeMeInterfaceField that = (WithSerializeMeInterfaceField) o;
            return Objects.equals(inner, that.inner);
        }

        @Override
        public int hashCode() {
            return Objects.hash(inner);
        }
    }
}
