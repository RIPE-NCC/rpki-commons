package net.ripe.rpki.commons.crypto.crl;

import lombok.EqualsAndHashCode;
import lombok.Value;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.util.UTC;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import static net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper.*;

public class X509Crl implements CertificateRepositoryObject {

    private static final long serialVersionUID = 1L;

    private final byte[] encoded;

    private transient X509CRL crl;

    public X509Crl(byte[] encoded) { //NOPMD - ArrayIsStoredDirectly
        Validate.notNull(encoded);
        this.encoded = encoded;
    }

    public X509Crl(X509CRL crl) {
        Validate.notNull(crl);
        try {
            this.crl = crl;
            this.encoded = crl.getEncoded();
        } catch (CRLException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public byte[] getEncoded() {
        return encoded;
    }


    public X509CRL getCrl() {
        if (crl == null) {
            crl = makeX509CRLFromEncoded(encoded);
        }
        return crl;
    }

    public static X509Crl parseDerEncoded(byte[] encoded, ValidationResult validationResult) {
        try {
            X509Crl crl = new X509Crl(makeX509CRLFromEncoded(encoded));
            validationResult.pass(ValidationString.CRL_PARSED);
            return crl;
        } catch (IllegalArgumentException e) {
            validationResult.error(ValidationString.CRL_PARSED);
            return null;
        }
    }

    private static X509CRL makeX509CRLFromEncoded(byte[] encoded) {
        if (encoded == null) {
            return null;
        }
        try {
            try (final ByteArrayInputStream in = new ByteArrayInputStream(encoded)) {
                final CertificateFactory factory = CertificateFactory.getInstance("X.509");
                return (X509CRL) factory.generateCRL(in);
            } catch (final CertificateException | CRLException e) {
                throw new IllegalArgumentException(e);
            }
        } catch (final IOException e) {
            throw new RuntimeException("Error managing CRL I/O stream", e);
        }
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(encoded);
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final X509Crl other = (X509Crl) obj;
        return Arrays.equals(encoded, other.encoded);
    }


    public byte[] getAuthorityKeyIdentifier() {
        return X509CertificateUtil.getAuthorityKeyIdentifier(getCrl());
    }

    public DateTime getThisUpdateTime() {
        return UTC.dateTime(getCrl().getThisUpdate());
    }

    public DateTime getNextUpdateTime() {
        return UTC.dateTime(getCrl().getNextUpdate());
    }

    public X500Principal getIssuer() {
        return getCrl().getIssuerX500Principal();
    }

    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        X509CrlValidator crlValidator = new X509CrlValidator(options, result, context.getCertificate());
        crlValidator.validate(location, this);
    }

    @Override
    public void validate(String location,
                         CertificateRepositoryObjectValidationContext context,
                         X509Crl crl,
                         URI crlUri,
                         ValidationOptions options,
                         ValidationResult result) {
        validate(location, context, null, options, result);
    }

    @Override
    public boolean isPastValidityTime() {
        return getNextUpdateTime().isBeforeNow();
    }

    @Override
    public boolean isRevoked() {
        return false;
    }

    public int getVersion() {
        return getCrl().getVersion();
    }

    public String getSigAlgName() {
        return getCrl().getSigAlgName();
    }

    public SortedSet<Entry> getRevokedCertificates() {
        SortedSet<Entry> result = new TreeSet<Entry>();
        Set<? extends X509CRLEntry> entries = getCrl().getRevokedCertificates();
        if (entries != null) {
            for (X509CRLEntry entry : entries) {
                result.add(new Entry(entry));
            }
        }
        return result;
    }

    public Entry getRevokedCertificate(BigInteger serialNumber) {
        X509CRLEntry entry = getCrl().getRevokedCertificate(serialNumber);
        return entry == null ? null : new Entry(entry);
    }

    public BigInteger getNumber() {
        try {
            byte[] extensionValue = getCrl().getExtensionValue(Extension.cRLNumber.getId());
            if (extensionValue == null) {
                return null;
            }
            ASN1Integer number = (ASN1Integer) JcaX509ExtensionUtils.parseExtensionValue(extensionValue);
            return number.getPositiveValue();
        } catch (IOException e) {
            throw new X509CrlException("cannot get CRLNumber extension from CRL", e);
        }
    }

    @Override
    public URI getCrlUri() {
        return null;
    }

    /**
     * This method is required by the interface, but should never be called
     * on X509Crl objects. it's pointless. They don't have an AIA.
     *
     * @throws UnsupportedOperationException whenever it is called
     */
    @Override
    public URI getParentCertificateUri() {
        throw new UnsupportedOperationException();
    }

    public void verify(PublicKey publicKey) throws SignatureException {
        try {
            getCrl().verify(publicKey, DEFAULT_SIGNATURE_PROVIDER);
        } catch (InvalidKeyException | CRLException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public boolean isRevoked(X509Certificate certificate) {
        return getCrl().isRevoked(certificate);
    }

    public static class X509CRLEntryComparator implements Comparator<X509CRLEntry> {
        @Override
        public int compare(X509CRLEntry o1, X509CRLEntry o2) {
            return o1.getSerialNumber().compareTo(o2.getSerialNumber());
        }
    }

    @Value
    public static class Entry implements Comparable<Entry>, Serializable {
        private static final long serialVersionUID = 1L;
        private final BigInteger serialNumber;
        private final DateTime revocationDateTime;

        public Entry(BigInteger serial, DateTime revocationDateTime) {
            Validate.notNull(serial, "serial is required");
            Validate.notNull(revocationDateTime, "revocationDateTime is required");
            this.serialNumber = serial;
            this.revocationDateTime = revocationDateTime.withMillisOfSecond(0);
        }

        public Entry(X509CRLEntry entry) {
            this.serialNumber = entry.getSerialNumber();
            this.revocationDateTime = UTC.dateTime(entry.getRevocationDate());
        }

        @Override
        public int compareTo(Entry o) {
            return getSerialNumber().compareTo(o.getSerialNumber());
        }
    }
}
