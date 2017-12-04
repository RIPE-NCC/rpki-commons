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
package net.ripe.rpki.commons.crypto.rfc3779;

import net.ripe.ipresource.IpAddress;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;

import java.util.SortedMap;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;

/**
 * Parses the certificate resource extensions as specified in RFC3779. Resource
 * inheritance is not yet supported.
 * <p/>
 * The methods in this class are named after the grammar rules in RFC3779,
 * prefixed with "derTo".
 */
public class ResourceExtensionParser {

    private static final AddressFamily[] SUPPORTED_ADDRESS_FAMILIES = new AddressFamily[]{AddressFamily.IPV4, AddressFamily.IPV6};


    /**
     * Parses the IP address blocks extension and merges all address families
     * into a single {@link IpResourceSet} containing both IPv4 and IPv6
     * addresses. Maps an {@link AddressFamily} to <code>null</code> when the
     * resource of this type are inherited. If no resources are specified it is
     * mapped to an empty resource set.
     */
    public SortedMap<AddressFamily, IpResourceSet> parseIpAddressBlocks(byte[] extension) {
        ASN1Primitive octetString = decode(extension);
        expect(octetString, ASN1OctetString.class);
        ASN1OctetString o = (ASN1OctetString) octetString;
        SortedMap<AddressFamily, IpResourceSet> map = derToIpAddressBlocks(decode(o.getOctets()));

        for (AddressFamily family : SUPPORTED_ADDRESS_FAMILIES) {
            if (!map.containsKey(family)) {
                map.put(family, new IpResourceSet());
            }
        }

        for (AddressFamily addressFamily : map.keySet()) {
            Validate.isTrue(!addressFamily.hasSubsequentAddressFamilyIdentifier(), "SAFI not supported");
        }

        return map;
    }

    /**
     * Parses the AS Identifier extension. All ASNUM entries are returned as an
     * {@link IpResourceSet}. RDI information is not supported. Returns
     * <code>null</code> if the AS numbers are inherited.
     */
    public IpResourceSet parseAsIdentifiers(byte[] extension) {
        ASN1Primitive octetString = decode(extension);
        expect(octetString, ASN1OctetString.class);
        ASN1OctetString o = (ASN1OctetString) octetString;
        IpResourceSet[] resources = derToAsIdentifiers(decode(o.getOctets()));
        Validate.notNull(resources[1], "inheritance of resources has not been implemented yet");
        Validate.isTrue(resources[1].isEmpty(), "routing domain identifiers (RDI) not supported");
        return resources[0];
    }

    /**
     * IPAddrBlocks ::= SEQUENCE OF IPAddressFamily
     */
    SortedMap<AddressFamily, IpResourceSet> derToIpAddressBlocks(ASN1Encodable der) {
        ASN1Sequence seq = expect(der, ASN1Sequence.class);
        SortedMap<AddressFamily, IpResourceSet> map = new TreeMap<AddressFamily, IpResourceSet>();

        for (int i = 0; i < seq.size(); i++) {
            derToIpAddressFamily(seq.getObjectAt(i), map);
        }
        return map;
    }

    /**
     * IPAddressFamily ::= SEQUENCE { -- AFI & opt SAFI -- addressFamily OCTET
     * STRING (SIZE (2..3)), ipAddressChoice IPAddressChoice }
     */
    void derToIpAddressFamily(ASN1Encodable der, SortedMap<AddressFamily, IpResourceSet> map) {
        ASN1Sequence seq = expect(der, ASN1Sequence.class);
        Validate.isTrue(seq.size() == 2, "IpAddressFamily must have exactly two entries: addressFamily and IpAddressChoice");

        AddressFamily addressFamily = AddressFamily.fromDer(seq.getObjectAt(0));
        IpResourceSet resources = derToIpAddressChoice(addressFamily.toIpResourceType(), seq.getObjectAt(1));

        map.put(addressFamily, resources);
    }

    /**
     * IPAddressChoice ::= CHOICE { inherit NULL, -- inherit from issuer --
     * addressesOrRanges SEQUENCE OF IPAddressOrRange }
     */
    IpResourceSet derToIpAddressChoice(IpResourceType type, ASN1Encodable der) {
        if (der instanceof ASN1Null) {
            return null;
        } else if (der instanceof ASN1Sequence) {
            IpResourceSet result = new IpResourceSet();
            ASN1Sequence seq = (ASN1Sequence) der;
            for (int i = 0; i < seq.size(); i++) {
                result.add(derToIpAddressOrRange(type, seq.getObjectAt(i)));
            }
            return result;
        } else {
            throw new IllegalArgumentException("ASN1Null or ASN1Sequence expected, got: " + der);
        }
    }

    /**
     * IPAddressOrRange ::= CHOICE { addressPrefix IPAddress, addressRange
     * IPAddressRange }
     */
    IpResource derToIpAddressOrRange(IpResourceType type, ASN1Encodable der) {
        if (der instanceof ASN1Sequence) {
            return derToIpRange(type, der);
        } else if (der instanceof DERBitString) {
            return parseIpAddressAsPrefix(type, der);
        } else {
            throw new IllegalArgumentException("ASN1Sequence or DERBitString expected, got: " + der);
        }
    }

    /**
     * IPAddressRange ::= SEQUENCE { min IPAddress, max IPAddress }
     */
    IpResource derToIpRange(IpResourceType type, ASN1Encodable der) {
        ASN1Sequence sequence = expect(der, ASN1Sequence.class);
        Validate.isTrue(sequence.size() == 2, "IPRange MUST consist of two entries (start and end)");

        IpAddress start = parseIpAddress(type, sequence.getObjectAt(0), false);
        IpAddress end = parseIpAddress(type, sequence.getObjectAt(1), true);

        return IpRange.range(start, end);
    }

    /**
     * ASRange ::= SEQUENCE { min ASId, max ASId }
     */
    IpResourceRange derToAsRange(ASN1Encodable der) {
        ASN1Sequence seq = expect(der, ASN1Sequence.class);
        Validate.isTrue(seq.size() == 2, "ASN1Sequence with two elements expected");
        return parseAsId(seq.getObjectAt(0)).upTo(parseAsId(seq.getObjectAt(1)));
    }

    /**
     * ASIdOrRange ::= CHOICE { id ASId, range ASRange }
     */
    IpResource derToAsIdOrRange(ASN1Encodable der) {
        if (der instanceof ASN1Integer) {
            return parseAsId(der);
        } else if (der instanceof ASN1Sequence) {
            return derToAsRange(der);
        } else {
            throw new IllegalArgumentException("ASN1Integer or ASN1Sequence expected, got: " + der);
        }
    }

    /**
     * asIdsOrRanges ::= SEQUENCE OF ASIdOrRange
     */
    IpResourceSet derToAsIdsOrRanges(ASN1Encodable der) {
        expect(der, ASN1Sequence.class);
        ASN1Sequence seq = (ASN1Sequence) der;
        IpResourceSet result = new IpResourceSet();
        for (int i = 0; i < seq.size(); ++i) {
            result.add(derToAsIdOrRange(seq.getObjectAt(i)));
        }
        return result;
    }

    /**
     * ASIdentifierChoice ::= CHOICE { inherit NULL, -- inherit from issuer --
     * asIdsOrRanges SEQUENCE OF ASIdOrRange }
     */
    IpResourceSet derToAsIdentifierChoice(ASN1Encodable der) {
        if (der instanceof ASN1Null) {
            return null;
        } else if (der instanceof ASN1Sequence) {
            return derToAsIdsOrRanges(der);
        } else {
            throw new IllegalArgumentException("ASN1Null or ASN1Sequence expected, got: " + der);
        }
    }

    /**
     * ASIdentifiers ::= SEQUENCE { asnum [0] EXPLICIT ASIdentifierChoice
     * OPTIONAL, rdi [1] EXPLICIT ASIdentifierChoice OPTIONAL}
     *
     * @return an array of two elements: the first element is the set of ASNUM
     *         resources, the second element is the set of RDI resources. Each
     *         can be null, indicating the set is inherited from the issuing
     *         certificate. An empty resource set indicates no resources were
     *         specified in the certificate.
     */
    IpResourceSet[] derToAsIdentifiers(ASN1Encodable der) {
        expect(der, ASN1Sequence.class);
        ASN1Sequence seq = (ASN1Sequence) der;
        Validate.isTrue(seq.size() <= 2, "ASN1Sequence with 2 or fewer elements expected");

        IpResourceSet[] result = {new IpResourceSet(), new IpResourceSet()};
        for (int i = 0; i < seq.size(); ++i) {
            expect(seq.getObjectAt(i), ASN1TaggedObject.class);
            ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(i);
            Validate.isTrue(tagged.getTagNo() == 0 || tagged.getTagNo() == 1, "unknown tag no: " + tagged.getTagNo());
            result[tagged.getTagNo()] = derToAsIdentifierChoice(tagged.getObject());
        }
        return result;
    }

}
