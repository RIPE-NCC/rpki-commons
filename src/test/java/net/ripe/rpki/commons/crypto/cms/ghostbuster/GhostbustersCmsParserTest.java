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
package net.ripe.rpki.commons.crypto.cms.ghostbuster;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateInformationAccessDescriptor;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.validation.ValidationCheck;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.joda.time.DateTime;
import org.junit.Ignore;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static net.ripe.rpki.commons.validation.ValidationString.*;
import static org.junit.Assert.*;

public class GhostbustersCmsParserTest {

    private static final X500Principal TEST_DN = new X500Principal("CN=issuer");
    private static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;
    private static final URI TEST_ROA_LOCATION = URI.create("rsync://certificate/repository/filename.roa");
    private static final URI TEST_CA_LOCATION = URI.create("rsync://certificate/repository/ca.cer");
    private static final URI CRL_DP = URI.create("rsync://certificate/repository/filename.crl");
    private static final BigInteger ROA_CERT_SERIAL = BigInteger.TEN;

    @Ignore("This GBR actually does not conform to the RFC")
    @Test
    public void testShouldParseGoodGbr() throws Exception {
        String path = "src/test/resources/conformance/root/goodRealGbrNothingIsWrong.gbr";
        byte[] bytes = FileUtils.readFileToByteArray(new File(path));
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation("test1.gbr"), bytes);

        GhostbustersCms ghostbustersCms = parser.getGhostbustersCms();
        String vCard = ghostbustersCms.getVCardContent();
        assertEquals("BEGIN:VCARD\r\n" +
            "VERSION:3.0\r\n" +
            "ADR:;;5147 Crystal Springs Drive NE;Bainbridge Island;Washington;98110;Uni\r\n" +
            " ted States\r\n" +
            "EMAIL:randy@psg.com\r\n" +
            "FN:Randy Bush\r\n" +
            "N:;;;;\r\n" +
            "ORG:RGnet\\, LLC\r\n" +
            "TEL:+1 206 356 8341\r\n" +
            "END:VCARD\r\n", vCard);
    }

    @Test
    public void ghostbusters_record_must_have_vcard() {
        ValidationResult validationResult = validatePayload("");

        assertTrue(validationResult.hasFailures());
        ValidationCheck check = validationResult.getFailuresForCurrentLocation().iterator().next();
        assertEquals(GHOSTBUSTERS_RECORD_SINGLE_VCARD, check.getKey());
    }

    @Test
    public void ghostbusters_record_must_have_single_vcard() {
        ValidationResult validationResult = validatePayload("BEGIN:VCARD\r\nEND:VCARD\r\nBEGIN:VCARD\n" +
            "END:VCARD\n");

        assertTrue(validationResult.hasFailures());
        ValidationCheck check = validationResult.getFailuresForCurrentLocation().iterator().next();
        assertEquals(GHOSTBUSTERS_RECORD_SINGLE_VCARD, check.getKey());
    }

    private ValidationResult validatePayload(String vCardPayload) {
        byte[] ghostbustersCms = new GhostbustersCmsBuilder()
            .withCertificate(createCertificate())
            .withVCardPayload(vCardPayload)
            .withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER)
            .getEncoded(TEST_KEY_PAIR.getPrivate());

        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        ValidationResult validationResult = ValidationResult.withLocation("test2.gbr");
        parser.parse(validationResult, ghostbustersCms);
        return validationResult;
    }

    @Test(expected = IllegalArgumentException.class)
    public void testShouldParseBadGbr() throws Exception {
        String path = "src/test/resources/conformance/root/badGBRNotVCard.gbr";
        byte[] bytes = FileUtils.readFileToByteArray(new File(path));
        GhostbustersCmsParser parser = new GhostbustersCmsParser();
        parser.parse(ValidationResult.withLocation("test2.gbr"), bytes);
        parser.getGhostbustersCms().getVCardContent();
    }

    private static X509ResourceCertificate createCertificate() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(ROA_CERT_SERIAL);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withValidityPeriod(new ValidityPeriod(new DateTime().minusMinutes(1), new DateTime().plusYears(1)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        builder.withCrlDistributionPoints(CRL_DP);
        builder.withSubjectInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_AD_SIGNED_OBJECT, TEST_ROA_LOCATION));
        builder.withAuthorityInformationAccess(new X509CertificateInformationAccessDescriptor(X509CertificateInformationAccessDescriptor.ID_CA_CA_ISSUERS, TEST_CA_LOCATION));
        return builder.build();
    }
}
