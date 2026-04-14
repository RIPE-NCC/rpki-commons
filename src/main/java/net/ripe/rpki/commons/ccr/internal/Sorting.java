package net.ripe.rpki.commons.ccr.internal;

import lombok.experimental.UtilityClass;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.math.BigInteger;
import java.util.Comparator;

@UtilityClass
public class Sorting {
    public static final Comparator<SubjectKeyIdentifier> ski = Comparator.comparing(x -> new BigInteger(1, x.getKeyIdentifier()));
}
