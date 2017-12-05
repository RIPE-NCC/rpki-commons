/**
 * The BSD License
 *
 * Copyright (c) 2010-2018 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.commons.crypto.crl;

import com.google.common.io.Closer;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateUtil;
import net.ripe.rpki.commons.util.EqualsSupport;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

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
        final X509CRL crl;
        if (null != encoded) {
            try {
                final Closer closer = Closer.create();
                try {
                    final ByteArrayInputStream in = new ByteArrayInputStream(encoded);
                    final CertificateFactory factory = CertificateFactory.getInstance("X.509");
                    crl = (X509CRL) factory.generateCRL(in);
                } catch (final CertificateException e) {
                    throw closer.rethrow(new IllegalArgumentException(e));
                } catch (final CRLException e) {
                    throw closer.rethrow(new IllegalArgumentException(e));
                } catch (final Throwable t) {
                    throw closer.rethrow(t);
                } finally {
                    closer.close();
                }
            } catch (final IOException e) {
                throw new RuntimeException("Error managing CRL I/O stream", e);
            }
        } else {
            crl = null;
        }
        return crl;

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
        return new DateTime(getCrl().getThisUpdate(), DateTimeZone.UTC);
    }

    public DateTime getNextUpdateTime() {
        return new DateTime(getCrl().getNextUpdate(), DateTimeZone.UTC);
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
            ASN1Integer number = (ASN1Integer) X509ExtensionUtil.fromExtensionValue(extensionValue);
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
     * on X509Crl objects.. it's pointless. They don't have an AIA.
     *
     * @throws: {@link UnsupportedOperationException}
     */
    @Override
    public URI getParentCertificateUri() {
        throw new UnsupportedOperationException();
    }

    public void verify(PublicKey publicKey) throws SignatureException {
        try {
            getCrl().verify(publicKey, DEFAULT_SIGNATURE_PROVIDER);
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        } catch (CRLException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (NoSuchProviderException e) {
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

    public static class Entry extends EqualsSupport implements Comparable<Entry>, Serializable {
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
            this.revocationDateTime = new DateTime(entry.getRevocationDate(), DateTimeZone.UTC);
        }

        public BigInteger getSerialNumber() {
            return serialNumber;
        }

        public DateTime getRevocationDateTime() {
            return revocationDateTime;
        }

        @Override
        public int compareTo(Entry o) {
            return getSerialNumber().compareTo(o.getSerialNumber());
        }
    }
}
