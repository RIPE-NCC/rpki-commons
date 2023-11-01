package net.ripe.rpki.commons.crypto.cms.roa;

import com.google.common.collect.ImmutableSortedSet;
import com.google.common.io.BaseEncoding;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.KeyPairFactoryTest;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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
        subject.withSignatureProvider(ECDSA_SIGNATURE_PROVIDER);
    }

    @Test
    public void shouldGenerateRoaCms() {
        RoaCms result = subject.build(KeyPairFactoryTest.EC_TEST_KEY_PAIR.getPrivate());
        assertNotNull(result);
        assertNotNull(result.getEncoded());
        System.out.println(BaseEncoding.base64().encode(result.getEncoded()));
    }

    @Test
    public void shouldEncodeRoaIpAddress() {
        assertEncoded(ENCODED_ROA_IP_ADDRESS, subject.encodeRoaIpAddress(TEST_IPV4_PREFIX_1));
        assertEncoded(ENCODED_ROA_IP_ADDRESS_2, subject.encodeRoaIpAddress(TEST_IPV4_PREFIX_2));
    }

    @Test
    public void shouldEncodeRoaIpAddressFamily() {
        assertEncoded(ENCODED_ROA_IP_ADDRESS_FAMILY, subject.encodeRoaIpAddressFamily(AddressFamily.IPV4, Set.copyOf(ipv4Prefixes)));
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
