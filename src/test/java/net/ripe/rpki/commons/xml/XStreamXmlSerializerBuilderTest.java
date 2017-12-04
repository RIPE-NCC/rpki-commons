/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.xml;

import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.util.VersionedId;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Period;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.sql.Timestamp;
import java.util.regex.Pattern;

import static org.junit.Assert.*;


public class XStreamXmlSerializerBuilderTest {


    private static final boolean NOT_STRICT = false;

    @Test
    public void shouldCreateSerializer() {
        XStreamXmlSerializerBuilder<String> builder = new XStreamXmlSerializerBuilder<String>(String.class, NOT_STRICT);
        XStreamXmlSerializer<String> serializer = builder.build();

        String serializedData = serializer.serialize("foo");
        Assert.assertEquals("<string>foo</string>", serializedData);
    }

    @Test
    public void shouldAliasCommonsPackage() {
        XStreamXmlSerializerBuilder<ValidityPeriod> builder = new XStreamXmlSerializerBuilder<ValidityPeriod>(ValidityPeriod.class, NOT_STRICT);
        XStreamXmlSerializer<ValidityPeriod> serializer = builder.build();

        String serializedData = serializer.serialize(new ValidityPeriod());
        Assert.assertEquals("<ValidityPeriod/>", serializedData);
    }

    @Test
    public void shouldAliasIpResourceAndUseConverter() {
        XStreamXmlSerializerBuilder<IpResource> builder = new XStreamXmlSerializerBuilder<IpResource>(IpResource.class, NOT_STRICT);
        XStreamXmlSerializer<IpResource> serializer = builder.build();
        IpResource ipResource = IpResource.parse("10/8");

        String serializedData = serializer.serialize(ipResource);
        Assert.assertEquals("<resource>10.0.0.0/8</resource>", serializedData);
        assertEquals(ipResource, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasIpResourceSetAndUseConverter() {
        XStreamXmlSerializerBuilder<IpResourceSet> builder = new XStreamXmlSerializerBuilder<IpResourceSet>(IpResourceSet.class, NOT_STRICT);
        XStreamXmlSerializer<IpResourceSet> serializer = builder.build();
        IpResourceSet ipResourceSet = IpResourceSet.parse("10/8");

        String serializedData = serializer.serialize(ipResourceSet);
        Assert.assertEquals("<resource-set>10.0.0.0/8</resource-set>", serializedData);
        assertEquals(ipResourceSet, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasDateTimeAndUseConverter() {
        XStreamXmlSerializerBuilder<DateTime> builder = new XStreamXmlSerializerBuilder<DateTime>(DateTime.class, NOT_STRICT);
        XStreamXmlSerializer<DateTime> serializer = builder.build();
        DateTime dateTime = new DateTime(2011, 1, 31, 13, 59, 59, 0, DateTimeZone.UTC);

        String serializedData = serializer.serialize(dateTime);
        Assert.assertEquals("<datetime>2011-01-31T13:59:59Z</datetime>", serializedData);
        assertEquals(dateTime, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertDateTimeFromTimeStamp() {
        XStreamXmlSerializerBuilder<Timestamp> builder = new XStreamXmlSerializerBuilder<Timestamp>(Timestamp.class, NOT_STRICT);
        XStreamXmlSerializer<Timestamp> serializer = builder.build();
        Timestamp timestamp = new Timestamp(new DateTime(2011, 1, 31, 13, 59, 59, 0, DateTimeZone.UTC).getMillis());

        String serializedData = serializer.serialize(timestamp);
        Assert.assertEquals("<sql-timestamp>2011-01-31T13:59:59.000Z</sql-timestamp>", serializedData);
        assertEquals(timestamp, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertDateTimeFromReadablePeriod() {
        XStreamXmlSerializerBuilder<Period> builder = new XStreamXmlSerializerBuilder<Period>(Period.class, NOT_STRICT);
        XStreamXmlSerializer<Period> serializer = builder.build();
        DateTime now = new DateTime();
        Period period = new Period(now, now.plusHours(1));

        String serializedData = serializer.serialize(period);
        Assert.assertEquals("<org.joda.time.Period>PT1H</org.joda.time.Period>", serializedData);
        assertEquals(period, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldAliasPrincipalAndUseConverter() {
        XStreamXmlSerializerBuilder<X500Principal> builder = new XStreamXmlSerializerBuilder<X500Principal>(X500Principal.class, NOT_STRICT);
        XStreamXmlSerializer<X500Principal> serializer = builder.build();
        X500Principal principal = new X500Principal("CN=nl.bluelight");

        String serializedData = serializer.serialize(principal);
        Assert.assertEquals("<principal>CN=nl.bluelight</principal>", serializedData);
        assertEquals(principal, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertVersionedId() {
        XStreamXmlSerializerBuilder<VersionedId> builder = new XStreamXmlSerializerBuilder<VersionedId>(VersionedId.class, NOT_STRICT);
        XStreamXmlSerializer<VersionedId> serializer = builder.build();
        VersionedId versionedId = new VersionedId(1l, 2l);

        String serializedData = serializer.serialize(versionedId);
        Assert.assertEquals("<versionedId>1:2</versionedId>", serializedData);
        assertEquals(versionedId, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertX509ResourceCertificate() {
        XStreamXmlSerializerBuilder<X509ResourceCertificate> builder = new XStreamXmlSerializerBuilder<X509ResourceCertificate>(X509ResourceCertificate.class, NOT_STRICT);
        XStreamXmlSerializer<X509ResourceCertificate> serializer = builder.build();
        X509ResourceCertificate resourceCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate();

        String serializedData = serializer.serialize(resourceCertificate);
        Assert.assertTrue(Pattern.matches("<X509ResourceCertificate>\\s*<encoded>[^<]+</encoded>\\s*</X509ResourceCertificate>", serializedData));
        assertEquals(resourceCertificate, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertManifestCms() {
        XStreamXmlSerializerBuilder<ManifestCms> builder = new XStreamXmlSerializerBuilder<ManifestCms>(ManifestCms.class, NOT_STRICT);
        XStreamXmlSerializer<ManifestCms> serializer = builder.build();
        ManifestCms manifestCms = ManifestCmsTest.getRootManifestCms();

        String serializedData = serializer.serialize(manifestCms);
        Assert.assertTrue(Pattern.matches("<ManifestCms>\\s*<encoded>[^<]+</encoded>\\s*</ManifestCms>", serializedData));
        assertEquals(manifestCms, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldConvertRoaCms() {
        XStreamXmlSerializerBuilder<RoaCms> builder = new XStreamXmlSerializerBuilder<RoaCms>(RoaCms.class, NOT_STRICT);
        XStreamXmlSerializer<RoaCms> serializer = builder.build();
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        String serializedData = serializer.serialize(roaCms);
        Assert.assertTrue(Pattern.matches("<RoaCms>\\s*<encoded>[^<]+</encoded>\\s*</RoaCms>", serializedData));
        assertEquals(roaCms, serializer.deserialize(serializedData));
    }

    @Test
    public void shouldIgnoreUnknownElements() {
        XStreamXmlSerializerBuilder<String> builder = new XStreamXmlSerializerBuilder<String>(String.class, NOT_STRICT);
        XStreamXmlSerializer<String> serializer = builder.build();

        String deserializedData = serializer.deserialize("<string>sample string</string><foo/>");
        Assert.assertEquals("sample string", deserializedData);
    }

    @Test
    public void shouldAliasPackage() {
        XStreamXmlSerializerBuilder<SerializeMe> builder = new XStreamXmlSerializerBuilder<SerializeMe>(SerializeMe.class, NOT_STRICT);
        builder.withAliasPackage("test-alias", SerializeMe.class.getPackage().getName());
        XStreamXmlSerializer<SerializeMe> serializer = builder.build();

        String serializedData = serializer.serialize(new SerializeMe());
        Assert.assertEquals("<test-alias.XStreamXmlSerializerBuilderTest_-SerializeMe/>", serializedData);
    }

    private static class SerializeMe {
    }
}
