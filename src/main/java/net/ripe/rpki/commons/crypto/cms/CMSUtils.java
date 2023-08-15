package net.ripe.rpki.commons.crypto.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.util.io.TeeOutputStream;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.OutputStream;
import java.util.Collection;
import java.util.List;

// From original CMSUtils of Bouncy Castle, needed for modified CMSSignedDataGenerator.
public class CMSUtils {

    static <T extends ASN1Encodable> ASN1Set createDerSetFromList(List<T> derObjects) {
        ASN1EncodableVector v = new ASN1EncodableVector();
        for (T derObject : derObjects) {
            v.add(derObject);
        }
        return new DERSet(v);
    }

    static AlgorithmIdentifier fixAlgID(AlgorithmIdentifier algId) {
        if (algId.getParameters() == null) {
            return new AlgorithmIdentifier(algId.getAlgorithm(), DERNull.INSTANCE);
        }
        return algId;
    }

    static OutputStream attachSignersToOutputStream(Collection<SignerInfoGenerator> signers, OutputStream s) {
        OutputStream result = s;
        for (SignerInfoGenerator signer : signers) {
            result = getNullSafeTeeOutputStream(result, signer.getCalculatingOutputStream());
        }
        return result;
    }

    static @NotNull OutputStream getNullSafeOutputStream(@Nullable OutputStream s) {
        if (s != null) {
            return s;
        } else {
            return new OutputStream() {
                @Override
                public void write(int b) {
                }
            };
        }
    }

    static OutputStream getNullSafeTeeOutputStream(OutputStream s1,
                                                   OutputStream s2) {
        return s1 == null ? getNullSafeOutputStream(s2)
            : s2 == null ? getNullSafeOutputStream(s1) : new TeeOutputStream(s1, s2);
    }
}
