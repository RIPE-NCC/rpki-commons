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