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
package net.ripe.rpki.commons.provisioning.x509.pkcs10;

import net.ripe.rpki.commons.crypto.util.PregeneratedKeyPairFactory;
import net.ripe.rpki.commons.provisioning.ProvisioningObjectMother;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Test;

import javax.security.auth.x500.X500Principal;
import java.net.URI;
import java.security.KeyPair;

import static org.junit.Assert.*;


public class RpkiCaCertificateRequestBuilderParserTest {

    @Test
    public void shouldRoundTripBuildParseRpkiCaCertRequest() throws RpkiCaCertificateRequestParserException {

        RpkiCaCertificateRequestBuilder requestBuilder = new RpkiCaCertificateRequestBuilder();

        URI caRepositoryUri = URI.create("rsync://host/module/subdir/");
        URI manifestUri = URI.create("rsync://host/module/subdir/subject.mft");
        X500Principal subject = new X500Principal("CN=subject");
        KeyPair keyPair = PregeneratedKeyPairFactory.getInstance().generate();

        requestBuilder.withCaRepositoryUri(caRepositoryUri);
        requestBuilder.withManifestUri(manifestUri);
        requestBuilder.withSubject(subject);
        PKCS10CertificationRequest pkcs10Request = requestBuilder.build(keyPair);

        assertNotNull(pkcs10Request);

        RpkiCaCertificateRequestParser requestParser = new RpkiCaCertificateRequestParser(pkcs10Request);

        assertEquals(caRepositoryUri, requestParser.getCaRepositoryUri());
        assertEquals(manifestUri, requestParser.getManifestUri());
        assertEquals(keyPair.getPublic(), requestParser.getPublicKey());
    }

    @Test
    public void shouldBuildParseEncodedRpkiCaCertRequest() throws Exception {

        PKCS10CertificationRequest pkcs10Request = createRpkiCaCertificateRequest();

        assertNotNull(pkcs10Request);

        PKCS10CertificationRequest decodedPkcs10Request = new PKCS10CertificationRequest(pkcs10Request.getEncoded());

        RpkiCaCertificateRequestParser requestParser = new RpkiCaCertificateRequestParser(decodedPkcs10Request);

        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_REPO_URI, requestParser.getCaRepositoryUri());
        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_MFT_URI, requestParser.getManifestUri());
        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_NOTIFICATION_URI, requestParser.getNotificationUri());
        Assert.assertEquals(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_KEYPAIR.getPublic(), requestParser.getPublicKey());
    }

    public static PKCS10CertificationRequest createRpkiCaCertificateRequest() {
        RpkiCaCertificateRequestBuilder requestBuilder = new RpkiCaCertificateRequestBuilder();
        requestBuilder.withCaRepositoryUri(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_REPO_URI);
        requestBuilder.withManifestUri(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_MFT_URI);
        requestBuilder.withNotificationUri(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_NOTIFICATION_URI);
        requestBuilder.withSubject(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_CA_SUBJECT);
        PKCS10CertificationRequest pkcs10Request = requestBuilder.build(ProvisioningObjectMother.RPKI_CA_CERT_REQUEST_KEYPAIR);
        return pkcs10Request;
    }

}
