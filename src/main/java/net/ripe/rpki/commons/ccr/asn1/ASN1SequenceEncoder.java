package net.ripe.rpki.commons.ccr.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSequence;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class ASN1SequenceEncoder {
    private final List<ASN1Encodable> elements = new ArrayList<>();

    public static ASN1Primitive encode(List<? extends ASN1Encodable> elements) {
        return new ASN1SequenceEncoder().append(elements).encode();
    }

    public static ASN1Primitive encode(ASN1Encodable head, ASN1Encodable... tail) {
        return start(head).append(tail).encode();
    }

    public static ASN1SequenceEncoder start(ASN1Encodable... elements) {
        var encoder = new ASN1SequenceEncoder();
        encoder.append(elements);
        return encoder;
    }

    public ASN1SequenceEncoder append(ASN1Encodable... elements) {
        for (var x : elements) {
            this.elements.add(x);
        }
        return this;
    }

    public ASN1SequenceEncoder append(List<? extends ASN1Encodable> elements) {
        this.elements.addAll(elements);
        return this;
    }

    public ASN1SequenceEncoder append(Optional<? extends ASN1Encodable> element) {
        element.ifPresent(this.elements::add);
        return this;
    }

    public ASN1Primitive encode() {
        return new DERSequence(elements.toArray(ASN1Encodable[]::new));
    }
}
