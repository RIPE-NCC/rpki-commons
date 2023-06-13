package net.ripe.rpki.commons.crypto.cms.aspa;

import com.google.common.collect.ImmutableSortedSet;
import lombok.NonNull;
import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectBuilder;
import net.ripe.rpki.commons.crypto.util.Asn1Util;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLTaggedObject;

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

    public AspaCmsBuilder withCustomerAsn(@NonNull Asn customerAsn) {
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
     * ct-ASPA CONTENT-TYPE ::= { TYPE ASProviderAttestation IDENTIFIED BY id-ct-ASPA }
     * ASProviderAttestation ::= SEQUENCE {
     *     version [0]   INTEGER DEFAULT 0,
     *     customerASID  ASID,
     *     providers     ProviderASSet
     * }
     * ProviderASSet ::= SEQUENCE (SIZE(1..MAX)) OF ASID
     * </pre>
     */
    private byte[] encodeAspa() {
        Validate.notNull(customerAsn, "Customer AS ID must not be null");
        Validate.notEmpty(providerASSet, "ProviderASSet must not be empty");
        ASN1Encodable[] encodables = {
            // Version is needs to be 1, but needs to be explicitly tagged
            new DLTaggedObject(0, new ASN1Integer(1)),
            new ASN1Integer(customerAsn.getValue()),
            new DERSequence(providerASSet.stream().map(as ->new ASN1Integer(as.getProviderAsn().getValue()
            )).toArray(ASN1Encodable[]::new))
        };
        return Asn1Util.encode(new DERSequence(encodables));
    }
}
