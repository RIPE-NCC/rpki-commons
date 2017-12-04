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
package net.ripe.rpki.commons.crypto.cms.roa;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;

public class RoaCmsObjectMother {

    public static final Asn TEST_ASN = new Asn(Long.valueOf(65000));
    public static final RoaPrefix TEST_IPV4_PREFIX_1 = new RoaPrefix(IpRange.parse("10.64.0.0/12"), 24);
    public static final RoaPrefix TEST_IPV4_PREFIX_2 = new RoaPrefix(IpRange.parse("10.32.0.0/12"), null);
    public static final RoaPrefix TEST_IPV6_PREFIX = new RoaPrefix(IpRange.parse("2001:0:200::/39"), null);

    public static final X500Principal TEST_DN = new X500Principal("CN=Test");
    public static final KeyPair TEST_KEY_PAIR = KeyPairFactoryTest.TEST_KEY_PAIR;

    public static RoaCms getRoaCms() {
        ValidityPeriod validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusYears(1));
        return getRoaCms(validityPeriod);
    }

    public static RoaCms getRoaCms(ValidityPeriod validityPeriod) {
        return getRoaCms(validityPeriod, TEST_ASN);
    }

    public static RoaCms getRoaCms(ValidityPeriod validityPeriod, Asn asn) {
        List<RoaPrefix> ipv4Prefixes;
        List<RoaPrefix> allPrefixes;

        ipv4Prefixes = new ArrayList<RoaPrefix>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);

        allPrefixes = new ArrayList<RoaPrefix>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);

        return getRoaCms(allPrefixes, validityPeriod, asn);
    }

    public static RoaCms getRoaCms(List<RoaPrefix> prefixes, ValidityPeriod validityPeriod, Asn asn) {
        RoaCmsBuilder builder = new RoaCmsBuilder();
        builder.withCertificate(createCertificate(prefixes, validityPeriod));
        builder.withAsn(asn);
        builder.withPrefixes(prefixes);
        builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);

        return builder.build(TEST_KEY_PAIR.getPrivate());
    }

    private static X509ResourceCertificate createCertificate(List<RoaPrefix> prefixes, ValidityPeriod validityPeriod) {
        IpResourceSet resources = new IpResourceSet();
        for (RoaPrefix prefix : prefixes) {
            resources.add(prefix.getPrefix());
        }
        X509ResourceCertificateBuilder builder = createCertificateBuilder(resources, validityPeriod);
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        X509ResourceCertificate result = builder.build();
        return result;
    }

    private static X509ResourceCertificateBuilder createCertificateBuilder(IpResourceSet resources, ValidityPeriod validityPeriod) {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();
        builder.withCa(false).withIssuerDN(TEST_DN).withSubjectDN(TEST_DN).withSerial(BigInteger.TEN);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(TEST_KEY_PAIR);
        builder.withValidityPeriod(validityPeriod);
        builder.withResources(resources);
        return builder;
    }
}
