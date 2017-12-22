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

import net.ripe.rpki.commons.crypto.crl.X509Crl.Entry;
import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import net.ripe.rpki.commons.crypto.x509cert.X509CertificateBuilderHelper;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;

public class X509CrlBuilder {

    public static final int CRL_VERSION_2 = 2;

    private X500Principal issuerDN;
    private DateTime thisUpdateTime;
    private DateTime nextUpdateTime;
    private AuthorityKeyIdentifier authorityKeyIdentifier;
    private CRLNumber crlNumber;
    private String signatureProvider = X509CertificateBuilderHelper.DEFAULT_SIGNATURE_PROVIDER;

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
        this.authorityKeyIdentifier = BouncyCastleUtil.createAuthorityKeyIdentifier(authorityKey);
        return this;
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
        try {
            X509v2CRLBuilder generator = createCrlGenerator();
            ContentSigner signer = new JcaContentSignerBuilder(X509CertificateBuilderHelper.DEFAULT_SIGNATURE_ALGORITHM).setProvider(signatureProvider).build(key);
            return new X509Crl(generator.build(signer).getEncoded());
        } catch (OperatorCreationException e) {
            throw new X509CrlBuilderException(e);
        } catch (IOException e) {
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
        X509v2CRLBuilder generator = new X509v2CRLBuilder(X500Name.getInstance(issuerDN.getEncoded()), thisUpdateTime.toDate());
        generator.setNextUpdate(nextUpdateTime.toDate());
        generator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        generator.addExtension(Extension.cRLNumber, false, crlNumber);
        for (X509Crl.Entry entry : entries.values()) {
            generator.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDateTime().toDate(), 0);
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
