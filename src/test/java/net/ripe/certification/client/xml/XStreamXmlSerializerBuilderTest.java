package net.ripe.certification.client.xml;

import static org.junit.Assert.*;

import java.sql.Timestamp;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsTest;
import net.ripe.commons.certification.util.VersionedId;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Period;
import org.junit.Test;


public class XStreamXmlSerializerBuilderTest {


    @Test
    public void shouldCreateSerializer() {
        XStreamXmlSerializerBuilder<String> builder = new XStreamXmlSerializerBuilder<String>(String.class);
        XStreamXmlSerializer<String> serializer = builder.build();

        String serializedData = serializer.serialize("foo");
        assertEquals("<string>foo</string>", serializedData);
    }

    @Test
    public void shouldAliasCommonsPackage() {
        XStreamXmlSerializerBuilder<ValidityPeriod> builder = new XStreamXmlSerializerBuilder<ValidityPeriod>(ValidityPeriod.class);
        XStreamXmlSerializer<ValidityPeriod> serializer = builder.build();

        String serializedData = serializer.serialize(new ValidityPeriod());
        assertEquals("<commons.ValidityPeriod/>", serializedData);
    }

    @Test
    public void shouldAliasIpResourceAndUseConverter() {
        XStreamXmlSerializerBuilder<IpResource> builder = new XStreamXmlSerializerBuilder<IpResource>(IpResource.class);
        XStreamXmlSerializer<IpResource> serializer = builder.build();
        IpResource ipResource = IpResource.parse("10/8");

        String serializedData = serializer.serialize(ipResource);
        assertEquals("<resource>10.0.0.0/8</resource>", serializedData);
        assertEquals(ipResource, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasIpResourceSetAndUseConverter() {
        XStreamXmlSerializerBuilder<IpResourceSet> builder = new XStreamXmlSerializerBuilder<IpResourceSet>(IpResourceSet.class);
        XStreamXmlSerializer<IpResourceSet> serializer = builder.build();
        IpResourceSet ipResourceSet = IpResourceSet.parse("10/8");

        String serializedData = serializer.serialize(ipResourceSet);
        assertEquals("<resource-set>10.0.0.0/8</resource-set>", serializedData);
        assertEquals(ipResourceSet, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasDateTimeAndUseConverter() {
        XStreamXmlSerializerBuilder<DateTime> builder = new XStreamXmlSerializerBuilder<DateTime>(DateTime.class);
        XStreamXmlSerializer<DateTime> serializer = builder.build();
        DateTime dateTime = new DateTime(2011, 1, 31, 13, 59, 59, 0, DateTimeZone.UTC);

        String serializedData = serializer.serialize(dateTime);
        assertEquals("<datetime>2011-01-31T13:59:59.000Z</datetime>", serializedData);
        assertEquals(dateTime, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertDateTimeFromTimeStamp() {
        XStreamXmlSerializerBuilder<Timestamp> builder = new XStreamXmlSerializerBuilder<Timestamp>(Timestamp.class);
        XStreamXmlSerializer<Timestamp> serializer = builder.build();
        Timestamp timestamp = new Timestamp(new DateTime(2011, 1, 31, 13, 59, 59, 0, DateTimeZone.UTC).getMillis());

        String serializedData = serializer.serialize(timestamp);
        assertEquals("<sql-timestamp>2011-01-31T13:59:59.000Z</sql-timestamp>", serializedData);
        assertEquals(timestamp, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertDateTimeFromReadablePeriod() {
        XStreamXmlSerializerBuilder<Period> builder = new XStreamXmlSerializerBuilder<Period>(Period.class);
        XStreamXmlSerializer<Period> serializer = builder.build();
        DateTime now = new DateTime();
        Period period = new Period(now, now.plusHours(1));

        String serializedData = serializer.serialize(period);
        assertEquals("<org.joda.time.Period>PT1H</org.joda.time.Period>", serializedData);
        assertEquals(period, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasPrincipalAndUseConverter() {
        XStreamXmlSerializerBuilder<X500Principal> builder = new XStreamXmlSerializerBuilder<X500Principal>(X500Principal.class);
        XStreamXmlSerializer<X500Principal> serializer = builder.build();
        X500Principal principal = new X500Principal("CN=nl.bluelight");

        String serializedData = serializer.serialize(principal);
        assertEquals("<principal>CN=nl.bluelight</principal>", serializedData);
        assertEquals(principal, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertVersionedId() {
        XStreamXmlSerializerBuilder<VersionedId> builder = new XStreamXmlSerializerBuilder<VersionedId>(VersionedId.class);
        XStreamXmlSerializer<VersionedId> serializer = builder.build();
        VersionedId versionedId = new VersionedId(1l, 2l);

        String serializedData = serializer.serialize(versionedId);
        assertEquals("<versionedId>1:2</versionedId>", serializedData);
        assertEquals(versionedId, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertX509ResourceCertificate() {
        XStreamXmlSerializerBuilder<X509ResourceCertificate> builder = new XStreamXmlSerializerBuilder<X509ResourceCertificate>(X509ResourceCertificate.class);
        XStreamXmlSerializer<X509ResourceCertificate> serializer = builder.build();
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();

        String serializedData = serializer.serialize(resourceCertificate);
        assertTrue(Pattern.matches("<commons\\.x509cert\\.X509ResourceCertificate>\\s*<encoded>[^<]+</encoded>\\s*</commons\\.x509cert\\.X509ResourceCertificate>", serializedData));
        assertEquals(resourceCertificate, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertManifestCms() {
        XStreamXmlSerializerBuilder<ManifestCms> builder = new XStreamXmlSerializerBuilder<ManifestCms>(ManifestCms.class);
        XStreamXmlSerializer<ManifestCms> serializer = builder.build();
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

        String serializedData = serializer.serialize(manifestCms);
        assertTrue(Pattern.matches("<commons\\.cms\\.manifest\\.ManifestCms>\\s*<encoded>[^<]+</encoded>\\s*</commons\\.cms\\.manifest\\.ManifestCms>", serializedData));
        assertEquals(manifestCms, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertRoaCms() {
        XStreamXmlSerializerBuilder<RoaCms> builder = new XStreamXmlSerializerBuilder<RoaCms>(RoaCms.class);
        XStreamXmlSerializer<RoaCms> serializer = builder.build();
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        String serializedData = serializer.serialize(roaCms);
        assertTrue(Pattern.matches("<commons\\.cms\\.roa\\.RoaCms>\\s*<encoded>[^<]+</encoded>\\s*</commons\\.cms\\.roa\\.RoaCms>", serializedData));
        assertEquals(roaCms, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldIgnoreUnknownElements() {
        XStreamXmlSerializerBuilder<String> builder = new XStreamXmlSerializerBuilder<String>(String.class);
        XStreamXmlSerializer<String> serializer = builder.build();

        String deserializedData = serializer.deserialize("<string>sample string</string><foo/>");
        assertEquals("sample string", deserializedData);
    }

    @Test
    public void shouldAliasPackage() {
        XStreamXmlSerializerBuilder<SerializeMe> builder = new XStreamXmlSerializerBuilder<SerializeMe>(SerializeMe.class);
        builder.withAliasPackage("test-alias", SerializeMe.class.getPackage().getName());
        XStreamXmlSerializer<SerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new SerializeMe());
        assertEquals("<test-alias.XStreamXmlSerializerBuilderTest_-SerializeMe/>", serializedData);
    }

    private static class SerializeMe {
    }
}
