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
package net.ripe.rpki.commons.crypto.x509cert;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.rfc3779.ResourceExtensionEncoder;
import net.ripe.rpki.commons.crypto.rfc8209.RouterExtensionEncoder;
import net.ripe.rpki.commons.crypto.util.BouncyCastleUtil;
import org.apache.commons.lang.Validate;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;

/**
 * Fairly generic helper for X509CertificateBuilders. Intended to be used by
 * (delegated to, not extended) specific certificate builders.
 * <p/>
 * Because we want to maintain the pattern where a specific Certificate builder
 * can be chained like: builder.withValidity(val).withSubjectDn(subject) etc...
 * dynamic typing would be required.. hence delegation.
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

    private boolean router;

    private boolean addSubjectKeyIdentifier = true;

    private boolean addAuthorityKeyIdentifier = true;

    private URI[] crlDistributionPoints;

    private AccessDescription[] authorityInformationAccess;

    private AccessDescription[] subjectInformationAccess;

    private PolicyInformation[] policies;

    private EnumSet<IpResourceType> inheritedResourceTypes = EnumSet.noneOf(IpResourceType.class);

    public X509CertificateBuilderHelper withSignatureProvider(
            String signatureProvider) {
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

    public X509CertificateBuilderHelper withValidityPeriod(
            ValidityPeriod validityPeriod) {
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
     * Careful! You probably want to stick to the default. This method is here
     * mainly to allow for testing the parser -> it should reject sig algos not
     * allowed by RFC
     */
    public X509CertificateBuilderHelper withSignatureAlgorithm(
            String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    public X509CertificateBuilderHelper withKeyUsage(int keyUsage) {
        this.keyUsage = keyUsage;
        return this;
    }

    public X509CertificateBuilderHelper withCa(boolean ca) {
        this.ca = ca;
        this.router = !ca;
        return this;
    }

    public X509CertificateBuilderHelper withRouter(boolean router) {
        this.router = router;
        this.ca = !router;
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

    public X509CertificateBuilderHelper withAuthorityInformationAccess(
            X509CertificateInformationAccessDescriptor... descriptors) {
        authorityInformationAccess = X509CertificateInformationAccessDescriptor
                .convertAccessDescriptors(descriptors);
        return this;
    }

    public X509CertificateBuilderHelper withSubjectInformationAccess(
            X509CertificateInformationAccessDescriptor... descriptors) {
        subjectInformationAccess = X509CertificateInformationAccessDescriptor
                .convertAccessDescriptors(descriptors);
        return this;
    }

    public X509CertificateBuilderHelper withPolicies(
            PolicyInformation... policies) {
        this.policies = policies;
        return this;
    }

    public X509CertificateBuilderHelper withInheritedResourceTypes(EnumSet<IpResourceType> resourceTypes) {
        this.inheritedResourceTypes = EnumSet.copyOf(resourceTypes);
        return this;
    }

    public X509Certificate generateCertificate() {
        X509v3CertificateBuilder certificateGenerator = createCertificateGenerator();
        try {
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(signatureProvider).build(signingKeyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(certificateGenerator.build(signer));
        } catch (IllegalStateException | OperatorCreationException | CertificateException e) {
            throw new X509ResourceCertificateBuilderException(e);
        }
    }

    /**
     * Override this to add your extensions to the certificate generator
     */
    protected X509v3CertificateBuilder createCertificateGenerator() {
        try {
            X509v3CertificateBuilder generator = createX509V3CertificateGenerator();

            if (addSubjectKeyIdentifier) {
                addSubjectKeyIdentifier(generator);
            }
            if (addAuthorityKeyIdentifier) {
                addAuthorityKeyIdentifier(generator);
            }
            if (ca) {
                addCaBit(generator);
            }
            if (router) {
                addBgpExtension(generator);
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
            if (policies != null && policies.length > 0) {
                addPolicies(generator);
            }
            if (resources != null) {
                addResourceExtensions(generator);
            }
            return generator;
        } catch (CertIOException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new X509ResourceCertificateBuilderException(e);
        }
    }

    private void addBgpExtension(X509v3CertificateBuilder generator) throws CertIOException {
        generator.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.getInstance(RouterExtensionEncoder.OID_KP_BGPSEC_ROUTER)));
    }

    private X509v3CertificateBuilder createX509V3CertificateGenerator() {
        validateCertificateFields();
        return new X509v3CertificateBuilder(
                BouncyCastleUtil.principalToName(issuerDN),
                serial,
                new Date(validityPeriod.getNotValidBefore().getMillis()),
                new Date(validityPeriod.getNotValidAfter().getMillis()),
                BouncyCastleUtil.principalToName(subjectDN),
                BouncyCastleUtil.createSubjectPublicKeyInfo(publicKey));
    }

    private void validateCertificateFields() {
        Validate.notNull(issuerDN, "no issuerDN");
        Validate.notNull(subjectDN, "no subjectDN");
        Validate.notNull(serial, "no serial");
        Validate.notNull(publicKey, "no publicKey");
        Validate.notNull(signingKeyPair, "no signingKeyPair");
        Validate.notNull(validityPeriod, "no validityPeriod");
        if (!ca) {
            Validate.isTrue((keyUsage & KeyUsage.keyCertSign) == 0,
                    "keyCertSign only allowed for ca");
        }
    }

    private void addSubjectKeyIdentifier(X509v3CertificateBuilder generator) throws InvalidKeyException, CertIOException, NoSuchAlgorithmException {
        generator.addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey));
    }

    private void addAuthorityKeyIdentifier(X509v3CertificateBuilder generator) throws InvalidKeyException, CertIOException {
        generator.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                BouncyCastleUtil.createAuthorityKeyIdentifier(signingKeyPair.getPublic()));
    }

    private void addCaBit(X509v3CertificateBuilder generator) throws CertIOException {
        generator.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
    }

    private void addKeyUsage(X509v3CertificateBuilder generator) throws CertIOException {
        generator.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
    }

    private void addAIA(X509v3CertificateBuilder generator) throws CertIOException {
        generator.addExtension(Extension.authorityInfoAccess, false,
                AuthorityInformationAccess.getInstance(new DERSequence(authorityInformationAccess)));
    }

    private void addSIA(X509v3CertificateBuilder generator) throws CertIOException {
        generator.addExtension(Extension.subjectInfoAccess, false,
                AuthorityInformationAccess.getInstance(new DERSequence(subjectInformationAccess)));
    }

    private void addCrlDistributionPoints(X509v3CertificateBuilder generator) throws CertIOException {
        CRLDistPoint crldp = convertToCrlDistributionPoint(crlDistributionPoints);
        generator.addExtension(Extension.cRLDistributionPoints, false, crldp);
    }

    private void addPolicies(X509v3CertificateBuilder generator) throws CertIOException {
        generator.addExtension(Extension.certificatePolicies, true, new DERSequence(policies));
    }

    private void addResourceExtensions(X509v3CertificateBuilder generator) throws CertIOException {
        ResourceExtensionEncoder encoder = new ResourceExtensionEncoder();

        for (IpResourceType inherited : inheritedResourceTypes) {
            if (resources.containsType(inherited)) {
                throw new IllegalArgumentException("resource set '" + resources + "' contains resources of inherited type " + inherited);
            }
        }

        ASN1Encodable encodedIPAddressBlocks = encoder.encodeIpAddressBlocks(
                inheritedResourceTypes.contains(IpResourceType.IPv4),
                inheritedResourceTypes.contains(IpResourceType.IPv6),
                resources);
        if (encodedIPAddressBlocks != null) {
            generator.addExtension(
                    ResourceExtensionEncoder.OID_IP_ADDRESS_BLOCKS, true,
                    encodedIPAddressBlocks);
        }

        ASN1Encodable encodedASNs = encoder.encodeAsIdentifiers(inheritedResourceTypes.contains(IpResourceType.ASN), resources);
        if (encodedASNs != null) {
            generator.addExtension(ResourceExtensionEncoder.OID_AUTONOMOUS_SYS_IDS, true, encodedASNs);
        }
    }

    /**
     * Generate a single distribution point where the names contains each URI.
     */
    private CRLDistPoint convertToCrlDistributionPoint(URI[] uris) {
        GeneralName[] seq = new GeneralName[uris.length];
        for (int i = 0; i < uris.length; ++i) {
            seq[i] = new GeneralName(GeneralName.uniformResourceIdentifier, uris[i].toString());
        }
        GeneralNames names = new GeneralNames(seq);
        DistributionPointName distributionPoint = new DistributionPointName(
                names);
        DistributionPoint[] dps = {new DistributionPoint(distributionPoint, null, null)};
        return new CRLDistPoint(dps);
    }
}
