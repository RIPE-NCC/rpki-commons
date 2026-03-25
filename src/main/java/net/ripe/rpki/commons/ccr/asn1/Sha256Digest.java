package net.ripe.rpki.commons.ccr.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

import java.math.BigInteger;
import java.util.HexFormat;

import static java.lang.Integer.min;
import static java.lang.Math.max;

public record Sha256Digest(BigInteger value) implements ASN1Encodable, Comparable<Sha256Digest> {
    public static Sha256Digest from(byte[] octets) {
        return new Sha256Digest(new BigInteger(1, octets));
    }

    public byte[] octets() {
        return copyOctets(value.toByteArray(), 32);
    }

    private static byte[] copyOctets(byte[] value, int size) {
        var octets = new byte[size];
        System.arraycopy(value, max(value.length - size, 0), octets, max(size - value.length, 0), min(value.length, size));
        return octets;
    }

    @Override
    public String toString() {
        return HexFormat.of().formatHex(octets());
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        return new DEROctetString(octets());
    }

    @Override
    public int compareTo(Sha256Digest other) {
        return value.compareTo(other.value);
    }
}
