package net.ripe.rpki.commons.crypto.crl;

import net.ripe.rpki.commons.crypto.crl.X509Crl.Entry;
import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jetbrains.annotations.NotNull;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;

public class X509CrlBuilder {

    public static final int CRL_VERSION_2 = 2;

    private X500Principal issuerDN;
    private Instant thisUpdateTime;
    private Instant nextUpdateTime;
    private AuthorityKeyIdentifier authorityKeyIdentifier;
    private CRLNumber crlNumber;
    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;

    private final SortedMap<BigInteger, X509Crl.Entry> entries = new TreeMap<>();


    public X509CrlBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public X509CrlBuilder withIssuerDN(X500Principal issuerDN) {
        this.issuerDN = issuerDN;
        return this;
    }

    public X509CrlBuilder withThisUpdateTime(Instant instant) {
        this.thisUpdateTime = instant;
        return this;
    }

    public Instant getThisUpdateTime() {
        return thisUpdateTime;
    }

    public X509CrlBuilder withNextUpdateTime(Instant instant) {
        this.nextUpdateTime = instant;
        return this;
    }

    public Instant getNextUpdateTime() {
        return nextUpdateTime;
    }

    /**
     * CRL number must be representable in 20 octets
     * https://tools.ietf.org/html/rfc5280#section-5.2.3
     */
    public X509CrlBuilder withNumber(BigInteger number) {
        if (number.signum() <= 0 || number.abs().bitLength() > 20 * 8) {
            throw new IllegalArgumentException(number + " CRL number must be positive and be representable by 20 octets or less.");
        }
        this.crlNumber = new CRLNumber(number);
        return this;
    }

    public X509CrlBuilder withAuthorityKeyIdentifier(PublicKey authorityKey) {
        this.authorityKeyIdentifier = BouncyCastleUtil.createAuthorityKeyIdentifier(authorityKey);
        return this;
    }

    public @NotNull X509CrlBuilder addEntry(@NotNull BigInteger serial, @NotNull Instant revocationTime) {
        Validate.isTrue(!entries.containsKey(serial), "duplicate CRL entry");
        entries.put(serial, new X509Crl.Entry(serial, revocationTime));
        return this;
    }

    public X509Crl.Entry getRevokedCertificate(BigInteger serial) {
        return entries.get(serial);
    }

    public X509CrlBuilder clearEntries() {
        entries.clear();
        return this;
    }

    public X509Crl build(PrivateKey key) {
        validateCrlFields();
        try {
            X509v2CRLBuilder generator = createCrlGenerator();
            ContentSigner signer = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM).setProvider(signatureProvider).build(key);
            return new X509Crl(generator.build(signer).getEncoded());
        } catch (OperatorCreationException | IOException e) {
            throw new X509CrlBuilderException(e);
        }
    }

    private void validateCrlFields() {
        Validate.notNull(issuerDN, "issuerDN is null");
        Validate.notNull(thisUpdateTime, "thisUpdateTime is null");
        Validate.notNull(nextUpdateTime, "nextUpdateTime is null");
        Validate.notNull(crlNumber, "crlNumber is null");
        Validate.notNull(authorityKeyIdentifier, "authorityKeyIdentifier is null");
    }

    private X509v2CRLBuilder createCrlGenerator() throws CertIOException {
        X509v2CRLBuilder generator = new X509v2CRLBuilder(X500Name.getInstance(issuerDN.getEncoded()), new Date(thisUpdateTime.toEpochMilli()));
        generator.setNextUpdate(new Date(nextUpdateTime.toEpochMilli()));
        generator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        generator.addExtension(Extension.cRLNumber, false, crlNumber);
        for (X509Crl.Entry entry : entries.values()) {
            generator.addCRLEntry(entry.serialNumber(), new Date(entry.revokedAt().toEpochMilli()), 0);
        }
        return generator;
    }

    /*
     * This method is used to determine if all the certs that need to be revoked are indeed revoked.
     * NOTE: The CRL may contain additional entries, in particular when a revoked certificate becomes expired.
     * However we DO NOT want to trigger re-issuance of the CRL in this case as this will generate a lot of
     * unnecessary churn.
     */
    public boolean isSatisfiedByEntries(X509Crl crl) {
        SortedSet<Entry> crlEntries = crl.getRevokedCertificates();
        return crlEntries.containsAll(entries.values());
    }
}
