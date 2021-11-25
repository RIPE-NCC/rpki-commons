/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.crypto.cms;

import net.ripe.rpki.commons.provisioning.x509.ProvisioningCmsCertificateBuilderTest;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERTaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Extension;
import java.util.Collections;
import java.util.List;

public class RPKISignedDataGeneratorTest {

    final RPKISignedDataGenerator rpkiCmsSubject = new RPKISignedDataGenerator();
    final CMSSignedDataGenerator bouncyCmsOriginal = new CMSSignedDataGenerator();
    final CMSAbsentContent cmsAbsentContent = new CMSAbsentContent();

    @Before
    public void setup() throws Exception{

        List<X509Extension> certificates = Collections.singletonList(ProvisioningCmsCertificateBuilderTest.TEST_CMS_CERT.getCertificate());
        rpkiCmsSubject.addCertificates(new JcaCertStore(certificates));
        bouncyCmsOriginal.addCertificates(new JcaCertStore(certificates));
    }

    @Test
    public void rpkiSignedDataGeneratorShouldGenerateSignedDataWithDERSequenceContentInfo() throws Exception {
        CMSSignedData rpkiCMS = rpkiCmsSubject.generate(cmsAbsentContent);
        ContentInfo contentInfo = rpkiCMS.toASN1Structure();
        assert(contentInfo.toASN1Primitive() instanceof DERSequence);

        //Third element of signed data, which is certificate should be DERTaggedObject
        DERSequence signedData = (DERSequence) contentInfo.getContent().toASN1Primitive();
        assert(signedData.getObjectAt(3).toASN1Primitive() instanceof DERTaggedObject);
    }

    @Test
    public void originalBCSignedDataGeneratorShouldGenerateBERSequenceContentInfo() throws Exception {
        CMSSignedData bcCMS = bouncyCmsOriginal.generate(cmsAbsentContent);
        ContentInfo contentInfo = bcCMS.toASN1Structure();
        assert(contentInfo.toASN1Primitive() instanceof BERSequence);

        //Third element of signed data, which is certificate should be BERTaggedObject
        BERSequence signedData = (BERSequence) contentInfo.getContent().toASN1Primitive();
        assert(signedData.getObjectAt(3).toASN1Primitive() instanceof BERTaggedObject);
    }


}