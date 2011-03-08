package net.ripe.commons.certification.crl;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.crl.X509Crl.Entry;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateBuilder;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.joda.time.DateTime;

public class X509CrlBuilder {

    public static final int CRL_VERSION_2 = 2;

    private X500Principal issuerDN;
    private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private AuthorityKeyIdentifierStructure authorityKeyIdentifier;
    private CRLNumber crlNumber;
    private String signatureProvider;

    private SortedMap<BigInteger, X509Crl.Entry> entries = new TreeMap<BigInteger, X509Crl.Entry>();


    public X509CrlBuilder withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public X509CrlBuilder withIssuerDN(X500Principal issuerDN) {
        this.issuerDN = issuerDN;
        return this;
    }

    public X509CrlBuilder withThisUpdateTime(DateTime instant) {
        this.thisUpdateTime = instant;
        return this;
    }

    public DateTime getThisUpdateTime() {
        return thisUpdateTime;
    }

    public X509CrlBuilder withNextUpdateTime(DateTime instant) {
        this.nextUpdateTime = instant;
        return this;
    }

    public DateTime getNextUpdateTime() {
        return nextUpdateTime;
    }

    public X509CrlBuilder withNumber(BigInteger number) {
        this.crlNumber = new CRLNumber(number);
        return this;
    }

    public X509CrlBuilder withAuthorityKeyIdentifier(PublicKey authorityKey) {
        try {
            this.authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(authorityKey);
            return this;
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public X509CrlBuilder addEntry(BigInteger serial, DateTime revocationTime) {
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
        X509V2CRLGenerator generator = createCrlGenerator();
        try {
            return new X509Crl(generator.generate(key, signatureProvider));
        } catch (InvalidKeyException e) {
            throw new X509CrlBuilderException(e);
        } catch (CRLException e) {
            throw new X509CrlBuilderException(e);
        } catch (IllegalStateException e) {
            throw new X509CrlBuilderException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new X509CrlBuilderException(e);
        } catch (NoSuchProviderException e) {
        	throw new X509CrlBuilderException(e);
        } catch (SignatureException e) {
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

    private X509V2CRLGenerator createCrlGenerator() {
        X509V2CRLGenerator generator = new X509V2CRLGenerator();
        generator.setIssuerDN(issuerDN);
        generator.setThisUpdate(thisUpdateTime.toDate());
        generator.setNextUpdate(nextUpdateTime.toDate());
        generator.setSignatureAlgorithm(X509ResourceCertificateBuilder.DEFAULT_SIGNATURE_ALGORITHM);
        generator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, authorityKeyIdentifier);
        generator.addExtension(X509Extensions.CRLNumber, false, crlNumber);
        for (X509Crl.Entry entry : entries.values()) {
            generator.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDateTime().toDate(), 0);
        }
        return generator;
    }

    public boolean isSatisfiedByEntries(X509Crl crl) {
        SortedSet<Entry> crlEntries = crl.getRevokedCertificates();
        return crlEntries.containsAll(entries.values());
    }
}
