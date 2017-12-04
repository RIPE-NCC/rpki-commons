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

import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParserTest.*;
import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsTest.*;
import static net.ripe.rpki.commons.crypto.util.Asn1UtilTest.*;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;
import static org.junit.Assert.*;


public class RoaCmsBuilderTest {

    private List<RoaPrefix> ipv4Prefixes;
    private List<RoaPrefix> allPrefixes;
    private RoaCmsBuilder subject;

    @Before
    public void setUp() {
        ipv4Prefixes = new ArrayList<RoaPrefix>();
        ipv4Prefixes.add(TEST_IPV4_PREFIX_1);
        ipv4Prefixes.add(TEST_IPV4_PREFIX_2);

        allPrefixes = new ArrayList<RoaPrefix>(ipv4Prefixes);
        allPrefixes.add(TEST_IPV6_PREFIX);

        subject = new RoaCmsBuilder();
        subject.withCertificate(createCertificate(allPrefixes));
        subject.withAsn(TEST_ASN);
        subject.withPrefixes(allPrefixes);
        subject.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
    }

    @Test
    public void shouldGenerateRoaCms() {
        RoaCms result = subject.build(KeyPairFactoryTest.TEST_KEY_PAIR.getPrivate());
        assertNotNull(result);
        assertNotNull(result.getEncoded());
    }

    @Test
    public void shouldEncodeRoaIpAddress() {
        assertEncoded(ENCODED_ROA_IP_ADDRESS, subject.encodeRoaIpAddress(TEST_IPV4_PREFIX_1));
        assertEncoded(ENCODED_ROA_IP_ADDRESS_2, subject.encodeRoaIpAddress(TEST_IPV4_PREFIX_2));
    }

    @Test
    public void shouldEncodeRoaIpAddressFamily() {
        assertEncoded(ENCODED_ROA_IP_ADDRESS_FAMILY, subject.encodeRoaIpAddressFamily(AddressFamily.IPV4, ipv4Prefixes));
    }

    @Test
    public void shouldEncodeRoaIpAddressFamilySequence() {
        assertEncoded(ENCODED_ROA_IP_ADDRESS_FAMILY_SEQUENCE_IPV4, subject.encodeRoaIpAddressFamilySequence(ipv4Prefixes));
        assertEncoded(ENCODED_ROA_IP_ADDRESS_FAMILY_SEQUENCE_ALL, subject.encodeRoaIpAddressFamilySequence(allPrefixes));
    }

    @Test
    public void shouldEncodeRouteOriginAttestation() {
        assertArrayEquals(ENCODED_ROUTE_ORIGIN_ATTESTATION, subject.encodeRouteOriginAttestation(TEST_ASN, ipv4Prefixes));
    }

}
