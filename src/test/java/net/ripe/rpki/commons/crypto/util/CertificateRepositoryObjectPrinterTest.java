package net.ripe.rpki.commons.crypto.util;

import net.ripe.rpki.commons.FixedDateRule;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsTest;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.util.UTC;
import org.bouncycastle.util.encoders.Hex;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;


public class CertificateRepositoryObjectPrinterTest {

    @Rule
    public FixedDateRule fixedDateRule = new FixedDateRule(new DateTime(2008, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC));

    @Test
    public void shouldPrintManifestCms() throws IOException {
        ManifestCms manifest = ManifestCmsTest.getRootManifestCms();
        String aki = new String(Hex.encode(BouncyCastleUtil.createAuthorityKeyIdentifier(
                ManifestCmsTest.ROOT_KEY_PAIR.getPublic()).getKeyIdentifier()));
        StringWriter output = new StringWriter();
        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), manifest);

        assertEquals("Object Type: RPKI Manifest\n" +
                             "Signing time: 2008-09-01T22:38:29.000Z\n" +
                             "Version: 0\n" +
                             "Number: 68\n" +
                             "This update time: 2008-09-01T22:43:29.000Z\n" +
                             "Next update time: 2008-09-02T22:43:29.000Z\n" +
                             "Authority Key Identifier: " + aki + "\n" +
                             "Filenames and hashes:\n"
                             + "    filename1.cer ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
                             + "    filename2.roa cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34\n",
                     output.getBuffer().toString());
    }

    @Test
    public void shouldPrintResourceCertificate() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        builder.withValidityPeriod(new ValidityPeriod(
            new DateTime(2008, 1, 4, 0, 0, 0, 0, DateTimeZone.UTC),
            new DateTime(2009, 1, 4, 0, 0, 0, 0, DateTimeZone.UTC)));
        X509ResourceCertificate certificate = builder.build();

        StringWriter output = new StringWriter();

        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), certificate);

        assertEquals("Object Type: X509Certificate with RFC3779 Internet Resource Extension\n" + "Serial: 900\n"
                + "Subject: CN=TEST-SELF-SIGNED-CERT\n" + "Not valid before: 2008-01-04T00:00:00.000Z\n"
                + "Not valid after:  2009-01-04T00:00:00.000Z\n" + "Resources: AS21212, 10.0.0.0/8, 192.168.0.0/16, ffce::/16\n", output.getBuffer()
                .toString());
    }

    @Test
    public void shouldPrintRoa() {
        StringWriter output = new StringWriter();
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), roaCms);

        assertEquals("Object Type: Route Origin Authorisation object\n" + "Signing time: 2007-12-31T23:59:00.000Z\n" + "ASN: AS42\n" + "Prefixes:\n"
                + "    10.32.0.0/12\n" + "    10.64.0.0/12 [24]\n" + "    2001:0:200::/39\n", output.getBuffer().toString());
    }

    @Test
    public void shouldPrintCRL() {
        X509CrlBuilder builder = X509CrlTest.getCrlBuilder();
        final DateTime now = UTC.dateTime();
        builder.addEntry(BigInteger.TEN, now.minusDays(1));
        builder.addEntry(BigInteger.valueOf(42), now.minusDays(3));
        X509Crl crl = builder.build(KeyPairFactoryTest.TEST_KEY_PAIR.getPrivate());

        StringWriter output = new StringWriter();

        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), crl);

        assertEquals("Object Type: Certificate Revocation List\n" + "CRL version: 2\n" + "Issuer: CN=issuer\n" + "Authority key identifier: "
                + KeyPairUtil.base64UrlEncode(crl.getAuthorityKeyIdentifier()) + "\n" + "Number: 10\n"
                + "This update time: 2008-01-01T00:00:00.000Z\n" + "Next update time: 2008-01-01T08:00:00.000Z\n"
                + "Revoked certificates serial numbers and revocation time:\n" + "    10 2007-12-31T00:00:00.000Z\n"
                + "    42 2007-12-29T00:00:00.000Z\n", output.getBuffer().toString());
    }

}
