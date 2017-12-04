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

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpAddress;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

import java.util.ArrayList;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Encodes the certificate resource extensions as specified in RFC3779. Resource
 * inheritance is not yet supported.
 * <p/>
 * The methods in this class are named after the grammar rules in RFC3779,
 * suffixed with "ToDer".
 */
public class ResourceExtensionEncoder {

    /**
     * id-pkix OBJECT IDENTIFIER ::= { iso(1) identified-organization(3) dod(6)
     * internet(1) security(5) mechanisms(5) pkix(7) }
     */
    public static final String OID_PKIX = "1.3.6.1.5.5.7";

    /**
     * id-pe OBJECT IDENTIFIER ::= { id-pkix 1 }
     */
    public static final String OID_PE = OID_PKIX + ".1";

    /**
     * id-pe-ipAddrBlocks OBJECT IDENTIFIER ::= { id-pe 7 }
     */
    public static final ASN1ObjectIdentifier OID_IP_ADDRESS_BLOCKS = new ASN1ObjectIdentifier(OID_PE + ".7");

    /**
     * id-pe-autonomousSysIds OBJECT IDENTIFIER ::= { id-pe 8 }
     */
    public static final ASN1ObjectIdentifier OID_AUTONOMOUS_SYS_IDS = new ASN1ObjectIdentifier(OID_PE + ".8");

    /**
     * Encode the IP Address Block extension for Resource Certificates. This
     * extension is identified by {@link #OID_IP_ADDRESS_BLOCKS}.
     *
     * @param inheritIpv4 inherit IPv4 resources from signing certificate.
     * @param inheritIpv6 inherit IPv6 resources from signing certificate.
     * @param resources   the set of IPv4 and IPv6 resources.
     * @return the DER encoding of the IP Address Block Extension.
     */
    public ASN1Object encodeIpAddressBlocks(boolean inheritIpv4, boolean inheritIpv6, IpResourceSet resources) {
        SortedMap<AddressFamily, IpResourceSet> addressBlocks = new TreeMap<AddressFamily, IpResourceSet>();

        if (inheritIpv4) {
            addressBlocks.put(AddressFamily.IPV4, null);
        } else if (resources.containsType(IpResourceType.IPv4)) {
            addressBlocks.put(AddressFamily.IPV4, resources);
        }

        if (inheritIpv6) {
            addressBlocks.put(AddressFamily.IPV6, null);
        } else if (resources.containsType(IpResourceType.IPv6)) {
            addressBlocks.put(AddressFamily.IPV6, resources);
        }

        return addressBlocks.isEmpty() ? null : ipAddressBlocksToDer(addressBlocks);
    }

    /**
     * Encode the AS Identifier extension for resource certificates. Only the
     * "asnum" part is encoded, since we do not use the "rdi" (routing domain
     * identifiers).
     *
     * @param inherit   inherit ASNs from signing certificate.
     * @param resources the set of ASNs.
     * @return the DER encoding of the AS Identifier extension.
     */
    public ASN1Object encodeAsIdentifiers(boolean inherit, IpResourceSet resources) {
        if (inherit || resources.containsType(IpResourceType.ASN)) {
            return asIdentifiersToDer(inherit, resources, false, new IpResourceSet());
        }
        return null;
    }

    /*
     * Internal support code.
     */

    /**
     * ASIdentifiers ::= SEQUENCE { asnum [0] EXPLICIT ASIdentifierChoice
     * OPTIONAL, rdi [1] EXPLICIT ASIdentifierChoice OPTIONAL}
     */
    ASN1Object asIdentifiersToDer(boolean inheritAsn, IpResourceSet asnResources, boolean inheritRdi, IpResourceSet rdiResources) {
        List<ASN1Encodable> seq = new ArrayList<ASN1Encodable>(2);
        if (inheritAsn || asnResources.containsType(IpResourceType.ASN)) {
            seq.add(new DERTaggedObject(0, asIdentifierChoiceToDer(inheritAsn, asnResources)));
        }
        if (inheritRdi || rdiResources.containsType(IpResourceType.ASN)) {
            seq.add(new DERTaggedObject(1, asIdentifierChoiceToDer(inheritRdi, rdiResources)));
        }
        return new DERSequence(seq.toArray(new ASN1Encodable[seq.size()]));
    }

    /**
     * ASIdentifierChoice ::= CHOICE { inherit NULL, -- inherit from issuer --
     * asIdsOrRanges SEQUENCE OF ASIdOrRange }
     */
    ASN1Encodable asIdentifierChoiceToDer(boolean inherit, IpResourceSet resources) {
        return inherit ? DERNull.INSTANCE : asIdsOrRangesToDer(resources);
    }

    /**
     * asIdsOrRanges ::= SEQUENCE OF ASIdOrRange
     */
    DERSequence asIdsOrRangesToDer(IpResourceSet resources) {
        List<ASN1Encodable> seq = new ArrayList<ASN1Encodable>();
        for (IpResource resource : resources) {
            if (IpResourceType.ASN == resource.getType()) {
                seq.add(asIdOrRangeToDer(IpResourceRange.range(resource.getStart(), resource.getEnd())));
            }
        }
        return new DERSequence(seq.toArray(new ASN1Encodable[seq.size()]));
    }

    /**
     * ASIdOrRange ::= CHOICE { id ASId, range ASRange }
     */
    ASN1Encodable asIdOrRangeToDer(IpResourceRange range) {
        return range.isUnique() ? asIdToDer((Asn) range.getStart()) : asRangeToDer(range);
    }

    /**
     * ASRange ::= SEQUENCE { min ASId, max ASId }
     */
    DERSequence asRangeToDer(IpResourceRange range) {
        ASN1Encodable[] seq = {asIdToDer((Asn) range.getStart()), asIdToDer((Asn) range.getEnd())};
        return new DERSequence(seq);
    }

    /**
     * ASId ::= INTEGER
     */
    ASN1Integer asIdToDer(Asn asn) {
        return new ASN1Integer(asn.getValue());
    }

    /**
     * IPAddrBlocks ::= SEQUENCE OF IPAddressFamily
     */
    ASN1Object ipAddressBlocksToDer(SortedMap<AddressFamily, IpResourceSet> resources) {
        List<ASN1Encodable> seq = new ArrayList<ASN1Encodable>(2);
        for (AddressFamily addressFamily : resources.keySet()) {
            seq.add(ipAddressFamilyToDer(addressFamily, resources.get(addressFamily)));
        }
        return new DERSequence(seq.toArray(new ASN1Encodable[seq.size()]));
    }

    /**
     * IPAddressFamily ::= SEQUENCE { -- AFI & opt SAFI -- addressFamily OCTET
     * STRING (SIZE (2..3)), ipAddressChoice IPAddressChoice }
     */
    ASN1Object ipAddressFamilyToDer(AddressFamily addressFamily, IpResourceSet resources) {
        IpResourceType type = addressFamily.toIpResourceType();
        ASN1Encodable[] seq = new ASN1Encodable[2];
        seq[0] = addressFamily.toDer();
        seq[1] = ipAddressChoiceToDer(type, resources);
        return new DERSequence(seq);
    }

    /**
     * IPAddressChoice ::= CHOICE { inherit NULL, -- inherit from issuer --
     * addressesOrRanges SEQUENCE OF IPAddressOrRange }
     */
    ASN1Encodable ipAddressChoiceToDer(IpResourceType type, IpResourceSet resources) {
        if (resources == null) {
            return DERNull.INSTANCE;
        }

        List<ASN1Encodable> addressesOrRanges = new ArrayList<ASN1Encodable>();
        for (IpResource resource : resources) {
            if (resource.getType() == type) {
                addressesOrRanges.add(ipAddressOrRangeToDer(asRange(resource)));
            }
        }
        Validate.notEmpty(addressesOrRanges, "no resources of type " + type + " in set");
        return new DERSequence(addressesOrRanges.toArray(new ASN1Encodable[addressesOrRanges.size()]));
    }

    private IpRange asRange(IpResource resource) {
        return IpRange.range((IpAddress) resource.getStart(), (IpAddress) resource.getEnd());
    }

    /**
     * IPAddressOrRange ::= CHOICE { addressPrefix IPAddress, addressRange
     * IPAddressRange }
     */
    ASN1Encodable ipAddressOrRangeToDer(IpRange range) {
        return range.isLegalPrefix() ? Asn1Util.encodeIpAddress(range) : ipRangeToDer(range);
    }

    /**
     * IPAddressRange ::= SEQUENCE { min IPAddress, max IPAddress }
     */
    DERSequence ipRangeToDer(IpRange range) {
        ASN1Encodable[] encodables = {startIpAddressToDer((IpAddress) range.getStart()), endIpAddressToDer((IpAddress) range.getEnd())};
        return new DERSequence(encodables);
    }

    /**
     * get the {DERBitString} for the ending IPv4 address; i.e. strip the least
     * significant ZERO values as described by rfc3779
     */
    private static DERBitString startIpAddressToDer(IpAddress address) {
        // Just keep track of the index of the last ONE bit
        int lastOne = address.getLeastSignificantOne();
        return Asn1Util.resourceToBitString(address, address.getType().getBitSize() - lastOne);
    }

    /**
     * get the {DERBitString} for the ending IPv4 address; i.e. strip the least
     * significant ONE values as described by rfc3779
     */
    private static DERBitString endIpAddressToDer(IpAddress address) {
        // Just keep track of the index of the last Zero bit
        int lastOne = address.getLeastSignificantZero();
        return Asn1Util.resourceToBitString(address.stripLeastSignificantOnes(), address.getType().getBitSize() - lastOne);
    }

}
