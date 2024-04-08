package net.ripe.rpki.commons.crypto.rfc3779;

import com.google.common.base.Preconditions;
import net.ripe.ipresource.*;
import net.ripe.rpki.commons.crypto.IllegalAsn1StructureException;
import org.bouncycastle.asn1.*;

import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.*;

/**
 * Parses the certificate resource extensions as specified in RFC3779. Resource
 * inheritance is not yet supported.
 *
 * The methods in this class are named after the grammar rules in RFC3779,
 * prefixed with "derTo".
 */
public class ResourceExtensionParser {

    private static final AddressFamily[] SUPPORTED_ADDRESS_FAMILIES = new AddressFamily[]{AddressFamily.IPV4, AddressFamily.IPV6};

    public ResourceExtension parse(X509Certificate certificate) {
        EnumSet<IpResourceType> inheritedResourceTypes = EnumSet.noneOf(IpResourceType.class);

        ImmutableResourceSet.Builder builder = new ImmutableResourceSet.Builder();
        byte[] ipAddressBlocksExtension = certificate.getExtensionValue(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId());
        if (ipAddressBlocksExtension != null) {
            if (!certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS.getId())) {
                throw new IllegalAsn1StructureException("id-pe-ipAddrBlocks must be marked as critical.");
            }
            SortedMap<AddressFamily, IpResourceSet> ipResources = parseIpAddressBlocks(ipAddressBlocksExtension);
            for (Map.Entry<AddressFamily, IpResourceSet> resourcesByType : ipResources.entrySet()) {
                if (resourcesByType.getValue() == null) {
                    inheritedResourceTypes.add(resourcesByType.getKey().toIpResourceType());
                } else {
                    builder.addAll(resourcesByType.getValue());
                }
            }
        }

        byte[] asnExtension = certificate.getExtensionValue(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId());
        if (asnExtension != null) {
            if (!certificate.getCriticalExtensionOIDs().contains(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS.getId())) {
                throw new IllegalAsn1StructureException("id-pe-autonomousSysIds must be marked as critical.");
            }
            IpResourceSet asResources = parseAsIdentifiers(asnExtension);
            if (asResources == null) {
                inheritedResourceTypes.add(IpResourceType.ASN);
            } else {
                builder.addAll(asResources);
            }
        }
        ImmutableResourceSet resources = builder.build();

        return ResourceExtension.of(inheritedResourceTypes, resources);
    }

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
            Preconditions.checkArgument(!addressFamily.hasSubsequentAddressFamilyIdentifier(), "SAFI not supported");
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
        Preconditions.checkNotNull(resources[1], "inheritance of resources has not been implemented yet");
        Preconditions.checkArgument(resources[1].isEmpty(), "routing domain identifiers (RDI) not supported");
        return resources[0];
    }

    /**
     * IPAddrBlocks ::= SEQUENCE OF IPAddressFamily
     */
    SortedMap<AddressFamily, IpResourceSet> derToIpAddressBlocks(ASN1Encodable der) {
        ASN1Sequence seq = expect(der, ASN1Sequence.class);
        SortedMap<AddressFamily, IpResourceSet> map = new TreeMap<>();

        Preconditions.checkArgument(seq.size() > 0, "IPAddrBlocks MUST NOT be empty");
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
        Preconditions.checkArgument(seq.size() == 2, "IpAddressFamily must have exactly two entries: addressFamily and IpAddressChoice");

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

            IpResource previous = null;
            for (int i = 0; i < seq.size(); i++) {
                IpResource current = derToIpAddressOrRange(type, seq.getObjectAt(i));
                // Check if previous and next are (1) in order and (2) not continuous
                if (previous != null) {
                    Preconditions.checkArgument(!previous.adjacent(current), "IP resources in extension MUST NOT be adjacent");
                    //    The addressesOrRanges element is a SEQUENCE OF IPAddressOrRange
                    //   types.  The addressPrefix and addressRange elements MUST be sorted
                    //   using the binary representation of:
                    //
                    //      <lowest IP address in range> | <prefix length>
                    UniqueIpResource start = current.getStart();
                    Preconditions.checkArgument(previous.getEnd().compareTo(start) < 0, "addressOrRanges MUST be sorted");
                }

                result.add(current);
                previous = current;
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
        Preconditions.checkArgument(sequence.size() == 2, "IPRange MUST consist of two entries (start and end)");

        IpAddress start = parseIpAddress(type, sequence.getObjectAt(0), false);
        IpAddress end = parseIpAddress(type, sequence.getObjectAt(1), true);

        return IpRange.range(start, end);
    }

    /**
     * ASRange ::= SEQUENCE { min ASId, max ASId }
     */
    IpResourceRange derToAsRange(ASN1Encodable der) {
        ASN1Sequence seq = expect(der, ASN1Sequence.class);
        Preconditions.checkArgument(seq.size() == 2, "ASN1Sequence with two elements expected");
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

        // The asIdsOrRanges element is a SEQUENCE of ASIdOrRange types.  Any
        // pair of items in the asIdsOrRanges SEQUENCE MUST NOT overlap.  Any
        // contiguous series of AS identifiers MUST be combined into a single
        // range whenever possible.  The AS identifiers in the asIdsOrRanges
        // element MUST be sorted by increasing numeric value.
        IpResource previous = null;
        Preconditions.checkArgument(seq.size() > 0, "asIdsOrRanges MUST NOT be empty");
        for (int i = 0; i < seq.size(); ++i) {
            IpResource current = derToAsIdOrRange(seq.getObjectAt(i));

            if (previous != null) {
                UniqueIpResource start = current.getStart();

                Preconditions.checkArgument(!start.adjacent(previous.getEnd()), "ASIdOrRange entries MUST NOT be adjacent");
                Preconditions.checkArgument(start.max(previous.getEnd()).equals(start), "ASIdOrRange entries MUST be sorted by increasing numeric value");
            }
            result.add(current);
            previous = current;
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
        try {
            ASN1Sequence seq = (ASN1Sequence) der;
            Preconditions.checkArgument(seq.size() <= 2, "ASN1Sequence with 2 or fewer elements expected");

            IpResourceSet[] result = {new IpResourceSet(), new IpResourceSet()};
            for (int i = 0; i < seq.size(); ++i) {
                expect(seq.getObjectAt(i), ASN1TaggedObject.class);
                ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(i);
                Preconditions.checkArgument(tagged.getTagNo() == 0 || tagged.getTagNo() == 1, "unknown tag no: " + tagged.getTagNo());
                Preconditions.checkArgument((tagged.getTagClass() & BERTags.CONTEXT_SPECIFIC) != 0, "element tag is context specific.");
                result[tagged.getTagNo()] = derToAsIdentifierChoice(tagged.getExplicitBaseObject());
            }
            return result;
        } catch (IllegalStateException e) {
            throw new IllegalAsn1StructureException("Could not parse AsIdentifiers extension", e);
        }
    }

}
