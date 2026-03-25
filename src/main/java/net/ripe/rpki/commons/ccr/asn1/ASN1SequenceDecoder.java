package net.ripe.rpki.commons.ccr.asn1;

import org.bouncycastle.asn1.*;

import java.text.ParseException;
import java.time.Instant;
import java.util.Optional;

import static net.ripe.rpki.commons.crypto.util.Asn1Util.expect;

public class ASN1SequenceDecoder {
    private final ASN1Sequence seq;
    private int idx = 0;

    public static ASN1SequenceDecoder from(ASN1Encodable asn1) {
        return new ASN1SequenceDecoder(expect(asn1, ASN1Sequence.class));
    }

    public ASN1SequenceDecoder(ASN1Sequence seq) {
        this.seq = seq;
    }

    private <A extends ASN1Encodable> Optional<A> peek(Class<A> type) {
        if (seq.size() <= idx) {
            return Optional.empty();
        }
        var obj = seq.getObjectAt(idx);
        if (!type.isAssignableFrom(obj.getClass())) {
            return Optional.empty();
        }
        return Optional.of(type.cast(obj));
    }

    public ASN1Encodable take() {
        return seq.getObjectAt(idx++);
    }

    public <A extends ASN1Encodable> A take(Class<A> type) {
        return expect(take(), type);
    }

    public <A extends ASN1Encodable> Optional<A> takeOptional(Class<A> type) {
        var obj = peek(type);
        obj.ifPresent(x -> idx++);
        return obj;
    }

    public Optional<ASN1Object> takeTaggedOptional(int tagno) {
        var tagged = peek(ASN1TaggedObject.class)
                .filter(x -> x.getTagNo() == tagno);
        tagged.ifPresent(x -> idx++);
        return tagged.map(ASN1TaggedObject::getExplicitBaseObject);
    }

    public Instant takeTime() {
        try {
            return take(ASN1GeneralizedTime.class).getDate().toInstant();
        } catch (ParseException e) {
            throw new InvalidContent("Invalid ASN1 timestamp", e);
        }
    }
}
