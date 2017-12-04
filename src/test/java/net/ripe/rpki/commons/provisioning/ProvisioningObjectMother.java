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
package net.ripe.rpki.commons.provisioning;

import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.crl.X509CrlBuilder;
import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateBuilder;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObject;
import net.ripe.rpki.commons.provisioning.cms.ProvisioningCmsObjectBuilder;
import net.ripe.rpki.commons.provisioning.payload.AbstractProvisioningPayload;
import net.ripe.rpki.commons.provisioning.payload.error.RequestNotPerformedResponsePayloadBuilderTest;
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayload;
import net.ripe.rpki.commons.provisioning.payload.issue.request.CertificateIssuanceRequestPayloadBuilderTest;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayload;
import net.ripe.rpki.commons.provisioning.payload.list.request.ResourceClassListQueryPayloadBuilder;
import net.ripe.rpki.commons.provisioning.payload.revocation.request.CertificateRevocationRequestPayloadBuilder;
import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest;
import net.ripe.rpki.commons.provisioning.x509.pkcs10.RpkiCaCertificateRequestBuilderParserTest;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.joda.time.DateTime;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.URI;
import java.security.KeyPair;
import java.security.cert.X509CRL;

public class ProvisioningObjectMother {

    public static final KeyPair TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();
    public static final KeyPair TEST_KEY_PAIR_2 = PregeneratedKeyPairFactory.getInstance().generate();
    public static final String DEFAULT_KEYPAIR_GENERATOR_PROVIDER = "SunRsaSign";
    public static final KeyPair SECOND_TEST_KEY_PAIR = PregeneratedKeyPairFactory.getInstance().generate();

    public static final X509CRL CRL = generateCrl();

    public static final X509ResourceCertificate X509_CA = generateX509();

    public static String PARENT_HANDLE = "test-parent-handle";
    public static String CHILD_HANDLE = "test-child-handle";

    public static URI RPKI_CA_CERT_REQUEST_CA_REPO_URI = URI.create("rsync://host/module/subdir/");
    public static URI RPKI_CA_CERT_REQUEST_CA_MFT_URI = URI.create("rsync://host/module/subdir/subject.mft");
    public static URI RPKI_CA_CERT_REQUEST_CA_NOTIFICATION_URI = URI.create("http://host:7788/module/subdir/notification.xml");

    public static X500Principal RPKI_CA_CERT_REQUEST_CA_SUBJECT = new X500Principal("CN=subject");
    public static KeyPair RPKI_CA_CERT_REQUEST_KEYPAIR = PregeneratedKeyPairFactory.getInstance().generate();
    public static PKCS10CertificationRequest RPKI_CA_CERT_REQUEST = RpkiCaCertificateRequestBuilderParserTest.createRpkiCaCertificateRequest();
    private static final CertificateIssuanceRequestPayload RPKI_CA_CERT_REQUEST_PAYLOAD = CertificateIssuanceRequestPayloadBuilderTest.createCertificateIssuanceRequestPayloadForPkcs10Request(RPKI_CA_CERT_REQUEST);

    public static ResourceClassListQueryPayload RESOURCE_CLASS_LIST_QUERY_PAYLOAD = createResourceListQueryPayload();

    private static X509ResourceCertificate generateX509() {
        X509ResourceCertificateBuilder builder = new X509ResourceCertificateBuilder();

        builder.withSubjectDN(new X500Principal("CN=zz.subject")).withIssuerDN(new X500Principal("CN=zz.issuer"));
        builder.withSerial(BigInteger.ONE);
        builder.withPublicKey(TEST_KEY_PAIR.getPublic());
        builder.withSigningKeyPair(SECOND_TEST_KEY_PAIR);
        DateTime now = new DateTime(2011, 3, 1, 0, 0, 0, 0);
        builder.withValidityPeriod(new ValidityPeriod(now, now.plusYears(5)));
        builder.withResources(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
        return builder.build();
    }

    private static X509CRL generateCrl() {
        X509CrlBuilder builder = new X509CrlBuilder();
        builder.withIssuerDN(new X500Principal("CN=nl.bluelight"));
        builder.withAuthorityKeyIdentifier(TEST_KEY_PAIR.getPublic());
        DateTime now = new DateTime();
        builder.withThisUpdateTime(now);
        builder.withNextUpdateTime(now.plusHours(24));
        builder.withNumber(BigInteger.TEN);

        return builder.build(TEST_KEY_PAIR.getPrivate()).getCrl();
    }

    public static ProvisioningCmsObject createResourceClassListQueryProvisioningCmsObject() {
        return createCmsForPayload(createResourceListQueryPayload());
    }

    public static ProvisioningCmsObject createResourceCertificateSignRequestProvisioningCmsObject() {
        return createCmsForPayload(RPKI_CA_CERT_REQUEST_PAYLOAD);
    }

    public static ProvisioningCmsObject createRequestNotPerformedResponseObject() {
        return createCmsForPayload(RequestNotPerformedResponsePayloadBuilderTest.NOT_PERFORMED_PAYLOAD);
    }

    public static ProvisioningCmsObject createRevocationRequestCmsObject() throws Exception {

        CertificateRevocationRequestPayloadBuilder revokePayloadBuilder = new CertificateRevocationRequestPayloadBuilder();
        revokePayloadBuilder.withClassName(RPKI_CA_CERT_REQUEST_PAYLOAD.getRequestElement().getClassName());
        revokePayloadBuilder.withPublicKey(RPKI_CA_CERT_REQUEST_KEYPAIR.getPublic());
        return createCmsForPayload(revokePayloadBuilder.build());
    }

    private static ProvisioningCmsObject createCmsForPayload(AbstractProvisioningPayload payloadXml) {
        payloadXml.setSender(CHILD_HANDLE);
        payloadXml.setRecipient(PARENT_HANDLE);
        ProvisioningCmsObjectBuilder builder = new ProvisioningCmsObjectBuilder()
                .withCmsCertificate(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate())
                .withCrl(CRL)
                .withPayloadContent(payloadXml);
        return builder.build(ProvisioningCmsCertificateBuilderTest.EE_KEYPAIR.getPrivate());
    }

    private static ResourceClassListQueryPayload createResourceListQueryPayload() {
        ResourceClassListQueryPayloadBuilder payloadBuilder = new ResourceClassListQueryPayloadBuilder();
        ResourceClassListQueryPayload payloadXml = payloadBuilder.build();
        return payloadXml;
    }


}
