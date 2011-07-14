/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.x509cert;

import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.rfc3779.ResourceExtensionEncoder;
import net.ripe.ipresource.InheritedIpResourceSet;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;


/**
 * Fairly generic helper for X509CertificateBuilders. Intended to be used by (delegated to, not
 * extended) specific certificate builders.
 *
 * Because we want to maintain the pattern where a specific Certificate builder can be chained like:
 * builder.withValidity(val).withSubjectDn(subject) etc... dynamic typing would be required.. hence delegation.
 *
 */
public final class X509CertificateBuilderHelper {

    public static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static final String DEFAULT_SIGNATURE_PROVIDER = "SunRsaSign";

    private String signatureProvider = DEFAULT_SIGNATURE_PROVIDER;

    private String signatureAlgorithm = DEFAULT_SIGNATURE_ALGORITHM;

    private BigInteger serial;

    private X500Principal subjectDN;

    private X500Principal issuerDN;

    private ValidityPeriod validityPeriod;

    private IpResourceSet resources;

    private PublicKey publicKey;

    private KeyPair signingKeyPair;

    private int keyUsage;

    private boolean ca;

    private boolean addSubjectKeyIdentifier = true;

    private boolean addAuthorityKeyIdentifier = true;

    private URI[] crlDistributionPoints;

    private AccessDescription[] authorityInformationAccess;

    private AccessDescription[] subjectInformationAccess;

    private PolicyInformation[] policies;

    public X509CertificateBuilderHelper withSignatureProvider(String signatureProvider) {
        this.signatureProvider = signatureProvider;
        return this;
    }

    public X509CertificateBuilderHelper withSerial(BigInteger serial) {
        this.serial = serial;
        return this;
    }

    public X509CertificateBuilderHelper withSubjectDN(X500Principal subjectDN) {
        this.subjectDN = subjectDN;
        return this;
    }

    public X509CertificateBuilderHelper withIssuerDN(X500Principal issuerDN) {
        this.issuerDN = issuerDN;
        return this;
    }

    public X509CertificateBuilderHelper withValidityPeriod(ValidityPeriod validityPeriod) {
        this.validityPeriod = validityPeriod;
        return this;
    }

    public X509CertificateBuilderHelper withResources(IpResourceSet resources) {
        this.resources = resources;
        return this;
    }

    public X509CertificateBuilderHelper withPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public X509CertificateBuilderHelper withSigningKeyPair(KeyPair signingKey) {
        this.signingKeyPair = signingKey;
        return this;
    }

    /**
     * Careful! You probably want to stick to the default. This method is here mainly
     * to allow for testing the parser -> it should reject sig algos not allowed by RFC
     */
    public X509CertificateBuilderHelper withSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public X509CertificateBuilderHelper withKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
        return this;
    }

    public X509CertificateBuilderHelper withCa(boolean ca) {
        this.ca = ca;
        return this;
    }

    public X509CertificateBuilderHelper withSubjectKeyIdentifier(boolean add) {
        this.addSubjectKeyIdentifier = add;
        return this;
    }

    public X509CertificateBuilderHelper withAuthorityKeyIdentifier(boolean add) {
        this.addAuthorityKeyIdentifier = add;
        return this;
    }

    public X509CertificateBuilderHelper withCrlDistributionPoints(URI... uris) {
        this.crlDistributionPoints = uris;
        return this;
    }

    public X509CertificateBuilderHelper withAuthorityInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        authorityInformationAccess = X509CertificateInformationAccessDescriptor.convertAccessDescriptors(descriptors);
        return this;
    }

    public X509CertificateBuilderHelper withSubjectInformationAccess(X509CertificateInformationAccessDescriptor... descriptors) {
        subjectInformationAccess = X509CertificateInformationAccessDescriptor.convertAccessDescriptors(descriptors);
        return this;
    }

    public X509CertificateBuilderHelper withPolicies(PolicyInformation... policies) {
        this.policies = policies;
        return this;
    }

    public X509Certificate generateCertificate() {
        X509V3CertificateGenerator certificateGenerator = createCertificateGenerator();
        try {
            return certificateGenerator.generate(signingKeyPair.getPrivate(), signatureProvider);
        } catch (CertificateEncodingException e) {
            throw new X509ResourceCertificateBuilderException(e);
        } catch (InvalidKeyException e) {
            throw new X509ResourceCertificateBuilderException(e);
        } catch (IllegalStateException e) {
            throw new X509ResourceCertificateBuilderException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new X509ResourceCertificateBuilderException(e);
        } catch (SignatureException e) {
            throw new X509ResourceCertificateBuilderException(e);
        } catch (NoSuchProviderException e) {
            throw new X509ResourceCertificateBuilderException(e);
        }
    }

    /**
     * Override this to add your extensions to the certificate generator
     */
    protected X509V3CertificateGenerator createCertificateGenerator() {
        X509V3CertificateGenerator generator = createX509V3CertificateGenerator();

        if (addSubjectKeyIdentifier) {
            addSubjectKeyIdentifier(generator);
        }
        if (addAuthorityKeyIdentifier) {
            addAuthorityKeyIdentifier(generator);
        }
        if (ca) {
            addCaBit(generator);
        }
        if (keyUsage != 0) {
            addKeyUsage(generator);
        }
        if (authorityInformationAccess != null) {
            addAIA(generator);
        }
        if (subjectInformationAccess != null) {
            addSIA(generator);
        }
        if (crlDistributionPoints != null) {
            Validate.noNullElements(crlDistributionPoints);
            addCrlDistributionPoints(generator);
        }
        if (policies != null) {
            addPolicies(generator);
        }
        if (resources != null) {
            addResourceExtensions(generator);
        }
        return generator;
    }

    private X509V3CertificateGenerator createX509V3CertificateGenerator() {
        validateCertificateFields();

        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
        generator.setNotBefore(new Date(validityPeriod.getNotValidBefore().getMillis()));
        generator.setNotAfter(new Date(validityPeriod.getNotValidAfter().getMillis()));
        generator.setIssuerDN(issuerDN);
        generator.setSerialNumber(serial);
        generator.setPublicKey(publicKey);
        generator.setSignatureAlgorithm(signatureAlgorithm);
        generator.setSubjectDN(subjectDN);
        return generator;
    }

    private void validateCertificateFields() {
        Validate.notNull(issuerDN, "no issuerDN");
        Validate.notNull(subjectDN, "no subjectDN");
        Validate.notNull(serial, "no serial");
        Validate.notNull(publicKey, "no publicKey");
        Validate.notNull(signingKeyPair, "no signingKeyPair");
        Validate.notNull(validityPeriod, "no validityPeriod");
        if (!ca) {
            Validate.isTrue((keyUsage & KeyUsage.keyCertSign) == 0, "keyCertSign only allowed for ca");
        }
    }

    private void addSubjectKeyIdentifier(X509V3CertificateGenerator generator) {
        try {
            generator.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(publicKey));
        } catch (CertificateParsingException e) {
            throw new X509ResourceCertificateBuilderException(e);
        }
    }

    private void addAuthorityKeyIdentifier(X509V3CertificateGenerator generator) {
        try {
            generator.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(signingKeyPair.getPublic()));
        } catch (InvalidKeyException e) {
            throw new X509ResourceCertificateBuilderException(e);
        }
    }

    private void addCaBit(X509V3CertificateGenerator generator) {
        generator.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(ca));
    }

    private void addKeyUsage(X509V3CertificateGenerator generator) {
        generator.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage));
    }

    private void addAIA(X509V3CertificateGenerator generator) {
        generator.addExtension(X509Extensions.AuthorityInfoAccess, false, new AuthorityInformationAccess(new DERSequence(authorityInformationAccess)));
    }

    private void addSIA(X509V3CertificateGenerator generator) {
        generator.addExtension(X509Extensions.SubjectInfoAccess, false, new AuthorityInformationAccess(new DERSequence(subjectInformationAccess)));
    }

    private void addCrlDistributionPoints(X509V3CertificateGenerator generator) {
        CRLDistPoint crldp = convertToCrlDistributionPoint(crlDistributionPoints);
        generator.addExtension(X509Extensions.CRLDistributionPoints, false, crldp);
    }

    private void addPolicies(X509V3CertificateGenerator generator) {
        generator.addExtension(X509Extensions.CertificatePolicies, true, new DERSequence(policies));
    }

    private void addResourceExtensions(X509V3CertificateGenerator generator) {
        ResourceExtensionEncoder encoder = new ResourceExtensionEncoder();

        boolean inherit = resources instanceof InheritedIpResourceSet;

        byte[] encodedIPAddressBlocks = encoder.encodeIpAddressBlocks(inherit, inherit, resources);
        if (encodedIPAddressBlocks != null) {
            generator.addExtension(ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS, true, encodedIPAddressBlocks);
        }

        byte[] encodedASNs = encoder.encodeAsIdentifiers(inherit, resources);
        if (encodedASNs != null) {
            generator.addExtension(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS, true, encodedASNs);
        }
    }

    /**
     * Generate a single distribution point where the names contains each URI.
     */
    private CRLDistPoint convertToCrlDistributionPoint(URI[] uris) {
        ASN1Encodable[] seq = new ASN1Encodable[uris.length];
        for (int i = 0; i < uris.length; ++i) {
            seq[i] = new GeneralName(GeneralName.uniformResourceIdentifier, uris[i].toString());
        }
        GeneralNames names = new GeneralNames(new DERSequence(seq));
        DistributionPointName distributionPoint = new DistributionPointName(names);
        DistributionPoint[] dps = {new DistributionPoint(distributionPoint, null, null)};
        return new CRLDistPoint(dps);
    }

}
