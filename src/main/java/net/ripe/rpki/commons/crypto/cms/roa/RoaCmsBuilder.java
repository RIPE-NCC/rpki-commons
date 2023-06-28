package net.ripe.rpki.commons.crypto.cms.roa;

import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectBuilder;
import net.ripe.rpki.commons.crypto.rfc3779.AddressFamily;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;

import java.security.PrivateKey;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Creates a RoaCms using the DER encoding specified in the ROA format standard.
 *
 * @see <a href="http://tools.ietf.org/html/draft-ietf-sidr-roa-format-03">ROA format</a>
 */
public class RoaCmsBuilder extends RpkiSignedObjectBuilder {

    private X509ResourceCertificate certificate;
    private Asn asn;
    private List<RoaPrefix> prefixes;
    private String signatureProvider;


    public RoaCmsBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public RoaCmsBuilder withAsn(Asn asn) {
        this.asn = asn;
        return this;
    }

    public RoaCmsBuilder withPrefixes(List<RoaPrefix> prefixes) {
        this.prefixes = prefixes;
        return this;

    }

    public RoaCmsBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public RoaCms build(PrivateKey privateKey) {
        String location = "unknown.roa";
        RoaCmsParser parser = new RoaCmsParser();
        parser.parse(ValidationResult.withLocation(location), generateCms(certificate.getCertificate(), privateKey, signatureProvider, RoaCms.CONTENT_TYPE, encodeRouteOriginAttestation(asn, prefixes)));
        return parser.getRoaCms();
    }

    /**
     * <pre>
     * ROAIPAddress ::= SEQUENCE {
     *     address IPAdress,
     *     maxLength INTEGER OPTIONAL }
     * </pre>
     */
    ASN1Object encodeRoaIpAddress(RoaPrefix prefix) {
        DERBitString address = Asn1Util.resourceToBitString(prefix.getPrefix().getStart(), prefix.getPrefix().getPrefixLength());
        ASN1Encodable[] encodables;
        if (prefix.getMaximumLength() == null) {
            encodables = new ASN1Encodable[]{address};
        } else {
            encodables = new ASN1Encodable[]{address, new ASN1Integer(prefix.getMaximumLength())};
        }
        return new DERSequence(encodables);
    }

    /**
     * Encode the <emph>unique</emph> addresses with the given addressFamily <b>in deterministic order</b>
     *
     * <pre>
     * ROAIPAddressFamily ::= SEQUENCE {
     *     addressFamily OCTET STRING (SIZE (2..3)),
     *     addresses SEQUENCE OF ROAIPAddress }
     * </pre>
     *
     * @requires all prefixes are of given addressFamily.
     */
    ASN1Encodable encodeRoaIpAddressFamily(AddressFamily addressFamily, List<RoaPrefix> prefixes) {
        Validate.isTrue(addressFamily == AddressFamily.IPV4 || addressFamily == AddressFamily.IPV6, "ROA can only contain IPv4 or IPv6 AFI");

        ASN1Encodable[] encodablePrefixes = prefixes.stream()
                .sorted()
                .map(this::encodeRoaIpAddress)
                .toArray(ASN1Encodable[]::new);

        ASN1Encodable[] seq = {addressFamily.toDer(), new DERSequence(encodablePrefixes)};
        return new DERSequence(seq);
    }

    /**
     * <pre>
     * SEQUENCE OF ROAIPAddressFamily
     * </pre>
     */
    ASN1Encodable encodeRoaIpAddressFamilySequence(List<RoaPrefix> prefixes) {
        Validate.isTrue(!prefixes.isEmpty(), "no prefixes");

        List<ASN1Encodable> encodables = Stream.concat(
            addRoaIpAddressFamily(IpResourceType.IPv4, prefixes),
            addRoaIpAddressFamily(IpResourceType.IPv6, prefixes)
        ).collect(Collectors.toList());

        Validate.isTrue(!encodables.isEmpty(), "no encodable prefixes");
        return new DERSequence(encodables.toArray(new ASN1Encodable[encodables.size()]));
    }

    /**
     * Encode the roaprefixes for the given address family.
     *
     * @param type IPv4 || IPv6
     * @param prefixes prefixes to encode
     * @return DER encoding of prefixes
     */
    private Stream<ASN1Encodable> addRoaIpAddressFamily(IpResourceType type, List<RoaPrefix> prefixes) {
        List<RoaPrefix> selectedPrefixes = prefixes.stream()
                .filter(roaPrefix -> type == roaPrefix.getPrefix().getType())
                .collect(Collectors.toList());

        if (selectedPrefixes.isEmpty()) {
            return Stream.empty();
        }

        return Stream.of(encodeRoaIpAddressFamily(AddressFamily.fromIpResourceType(type), selectedPrefixes));
    }

    private List<RoaPrefix> selectPrefixes(IpResourceType type, List<RoaPrefix> prefixes) {
        List<RoaPrefix> result = new ArrayList<RoaPrefix>();
        for (RoaPrefix roaPrefix : prefixes) {
            if (type == roaPrefix.getPrefix().getType()) {
                result.add(roaPrefix);
            }
        }
        return result;
    }

    /**
     * <pre>
     * RouteOriginAttestation ::= SEQUENCE {
     *    version [0] INTEGER DEFAULT 0,
     *    asID  ASID,
     *    ipAddrBlocks SEQUENCE OF ROAIPAddressFamily }
     *
     * ASID ::= INTEGER
     * </pre>
     * <p/>
     * Note: in DER encoding a field with a value equal to its default should
     * NOT be encoded. So the version field should not be present.
     */
    byte[] encodeRouteOriginAttestation(Asn asn, List<RoaPrefix> prefixes) {
        ASN1Encodable[] encodables = {new ASN1Integer(asn.getValue()), encodeRoaIpAddressFamilySequence(prefixes)};
        return Asn1Util.encode(new DERSequence(encodables));
    }
}
