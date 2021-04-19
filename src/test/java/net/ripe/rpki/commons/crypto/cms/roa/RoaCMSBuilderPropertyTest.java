/**
 * The BSD License
 *
 * Copyright (c) 2010-2020 RIPE NCC
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

import com.pholser.junit.quickcheck.Property;
import com.pholser.junit.quickcheck.generator.InRange;
import com.pholser.junit.quickcheck.runner.JUnitQuickcheck;
import net.ripe.ipresource.Asn;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsObjectMother.TEST_IPV4_PREFIX_1;
import static net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParserTest.TEST_IPV4_PREFIX_2;
import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitQuickcheck.class)
public class RoaCMSBuilderPropertyTest {

    @Property public void buildEncodedParseCheck(
            KeyPair keyPair,
            @InRange(min="1", max="65536")  long asNum
    ){
            List<RoaPrefix> prefixes = new ArrayList<>();
            prefixes.add(TEST_IPV4_PREFIX_1);
            prefixes.add(TEST_IPV4_PREFIX_2);

            RoaCmsBuilder builder = new RoaCmsBuilder();
            builder.withSignatureProvider(DEFAULT_SIGNATURE_PROVIDER);
            builder.withCertificate(RoaCmsTest.createCertificate(prefixes, keyPair));
            Asn asn = new Asn(asNum);
            builder.withAsn(asn);
            builder.withPrefixes(prefixes);
            RoaCms roaCms = builder.build(keyPair.getPrivate());

            RoaCmsParser roaParser = new RoaCmsParser();
            roaParser.parse("test.roa", roaCms.getEncoded());

            RoaCms parsedRoaCms = roaParser.getRoaCms();
            assertTrue(parsedRoaCms.getPrefixes().equals(prefixes));
            assertTrue(parsedRoaCms.getAsn().equals(asn));
    }


}

