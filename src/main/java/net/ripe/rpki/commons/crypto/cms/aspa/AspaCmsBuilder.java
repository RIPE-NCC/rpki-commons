package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectBuilder;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.jetbrains.annotations.NotNull;

import java.security.PrivateKey;

/**
 * Creates a {@link AspaCms} using the DER encoding.
 */
public class AspaCmsBuilder extends RpkiSignedObjectBuilder {

    private X509ResourceCertificate certificate;

    private String signatureProvider;

    private Asn customerAsn;

    private ImmutableSortedSet<ProviderAS> providerASSet;

    public AspaCmsBuilder withCertificate(X509ResourceCertificate certificate) {
        this.certificate = certificate;
        return this;
    }

    public AspaCmsBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public AspaCmsBuilder withCustomerAsn(@NotNull Asn customerAsn) {
        this.customerAsn = customerAsn;
        return this;
    }

    public AspaCmsBuilder withProviderASSet(Iterable<? extends ProviderAS> providerASSet) {
        this.providerASSet = ImmutableSortedSet.<ProviderAS>naturalOrder().addAll(providerASSet).build();
        return this;
    }

    public AspaCms build(PrivateKey privateKey) {
        String location = "unknown.asa";
        AspaCmsParser parser = new AspaCmsParser();
        parser.parse(ValidationResult.withLocation(location), getEncoded(privateKey));
        return parser.getAspa();
    }

    public byte[] getEncoded(PrivateKey privateKey) {
        return generateCms(certificate.getCertificate(), privateKey, signatureProvider, AspaCms.CONTENT_TYPE, encodeAspa());
    }

    /**
     * <pre>
     * ASProviderAttestation ::= SEQUENCE {
     *   version [0]   ASPAVersion DEFAULT v0,
     *   customerASID  ASID,
     *   providers     ProviderASSet
     * }
     *
     * ASPAVersion ::= INTEGER  { v0(0) }
     *
     * ProviderASSet ::= SEQUENCE (SIZE(1..MAX)) OF ProviderAS
     *
     * ProviderAS ::= SEQUENCE {
     *   providerASID  ASID,
     *   afiLimit      AddressFamilyIdentifier OPTIONAL
     * }
     *
     * ASID ::= INTEGER
     *
     * AddressFamilyIdentifier ::= OCTET STRING (SIZE (2))
     * </pre>
     */
    private byte[] encodeAspa() {
        Validate.notNull(customerAsn, "Customer AS ID must not be null");
        Validate.notEmpty(providerASSet, "ProviderASSet must not be empty");
        ASN1Encodable[] encodables = {
            // Version is default value, so must not be encoded
            new ASN1Integer(customerAsn.getValue()),
            new DERSequence(providerASSet.stream().map(as -> {
                if (as.getAfiLimit().isPresent()) {
                    return new DERSequence(new ASN1Encodable[] {
                        new ASN1Integer(as.getProviderAsn().getValue()),
                        as.getAfiLimit().get().toDer()
                    });
                } else {
                    return new DERSequence(new ASN1Encodable[] {
                        new ASN1Integer(as.getProviderAsn().getValue())
                    });
                }
            }).toArray(ASN1Encodable[]::new))
        };
        return Asn1Util.encode(new DERSequence(encodables));
    }
}
