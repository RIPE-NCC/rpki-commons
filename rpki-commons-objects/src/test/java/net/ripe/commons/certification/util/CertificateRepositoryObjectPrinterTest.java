package net.ripe.commons.certification.util;

import static org.junit.Assert.*;

import java.io.PrintWriter;
import java.io.StringWriter;

import net.ripe.commons.certification.FixedDateRule;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsTest;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlTest;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Rule;
import org.junit.Test;


public class CertificateRepositoryObjectPrinterTest {

    @Rule
    public FixedDateRule fixedDateRule = new FixedDateRule(new DateTime(2008, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC));


    @Test
    public void shouldPrintManifestCms() {
        ManifestCms manifest = ManifestCmsTest.getRootManifestCms();
        StringWriter output = new StringWriter();
        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), manifest);

        assertEquals(
                "Object Type: RPKI Manifest\n" +
                "Signing time: 2008-01-01T00:00:00.000Z\n" +
                "Version: 0\n" +
                "Number: 68\n" +
                "This update time: 2008-09-01T22:43:29.000Z\n" +
                "Next update time: 2008-09-02T06:43:29.000Z\n" +
                "Filenames and hashes:\n" +
                "    BaR cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34\n" +
                "    foo1 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
                output.getBuffer().toString());
    }


    @Test
    public void shouldPrintResourceCertificate() {
        X509ResourceCertificateBuilder builder = X509ResourceCertificateTest.createSelfSignedCaResourceCertificateBuilder();
        builder.withValidityPeriod(new ValidityPeriod(new DateTime(2008, 1, 4, 0, 0, 0, 0, DateTimeZone.UTC), new DateTime(2009, 1, 4, 0, 0, 0, 0, DateTimeZone.UTC)));
        X509ResourceCertificate certificate = builder.buildResourceCertificate();

        StringWriter output = new StringWriter();

        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), certificate);

        assertEquals(
                "Object Type: X509Certificate with RFC3779 Internet Resource Extension\n" +
                "Serial: 900\n" +
                "Subject: CN=TEST-SELF-SIGNED-CERT\n" +
                "Not valid before: 2008-01-04T00:00:00.000Z\n" +
                "Not valid after:  2009-01-04T00:00:00.000Z\n" +
                "Resources: AS21212, 10.0.0.0/8, 192.168.0.0/16, ffce::/16\n",
                output.getBuffer().toString());
    }



    @Test
    public void shouldPrintRoa() {
        StringWriter output = new StringWriter();
        RoaCms roaCms = RoaCmsTest.getRoaCms();

        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), roaCms);

        assertEquals(
                "Object Type: Route Origin Authorisation object\n" +
                "Signing time: 2008-01-01T00:00:00.000Z\n" +
                "ASN: AS42\n" +
                "Prefixes:\n" +
                "    10.64.0.0/12 [24]\n" +
                "    10.32.0.0/12\n" +
                "    2001:0:200::/39\n",
                output.getBuffer().toString());
    }

    @Test
    public void shouldPrintCRL() {
        X509Crl crl = X509CrlTest.createCrl();

        StringWriter output = new StringWriter();

        CertificateRepositoryObjectPrinter.print(new PrintWriter(output), crl);

        assertEquals(
                "Object Type: Certificate Revocation List\n" +
                "CRL version: 2\n" +
                "Issuer: CN=issuer\n" +
                "Authority key identifier: " + KeyPairUtil.base64UrlEncode(crl.getAuthorityKeyIdentifier()) + "\n" +
                "Number: 10\n" +
                "This update time: 2008-01-01T00:00:00.000Z\n" +
                "Next update time: 2008-01-01T08:00:00.000Z\n" +
                "Revoked certificates serial numbers and revocation time:\n" +
                "    10 2007-12-31T00:00:00.000Z\n" +
                "    42 2007-12-29T00:00:00.000Z\n",
                output.getBuffer().toString());
    }

}
