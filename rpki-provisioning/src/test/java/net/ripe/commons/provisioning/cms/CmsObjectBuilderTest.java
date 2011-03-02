package net.ripe.commons.provisioning.cms;

import org.junit.Test;

public class CmsObjectBuilderTest {

    private CmsObjectBuilder subject;


//    @Before
//    public void setUp() throws Exception {
//        subject =  new CmsObjectBuilder();
//    }

    @Test
    public void shouldBuildCmsObject() throws Exception {
//        subject.build(null);
//        createSelfSignedIdentityCertificate();
    }


//    private X509Certificate createSelfSignedIdentityCertificate() throws Exception {
//        KeyPair keyPair = generateKeyPair();
//
//        X509V3CertificateGenerator generator = new X509V3CertificateGenerator();
//        generator.setNotBefore(new Date(new  DateTime().minusDays(7).getMillis()));
//        generator.setNotAfter(new Date(new  DateTime().plusDays(7).getMillis()));
//        generator.setIssuerDN(new X500Principal("CN=nl.blelight"));
//        generator.setSerialNumber(BigInteger.ONE);
//        generator.setPublicKey(keyPair.getPublic());
//        generator.setSignatureAlgorithm("SHA256withRSA");
//        generator.setSubjectDN(new X500Principal("CN=nl.blelight"));
//
//        generator.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(keyPair.getPublic()));
//        //TODO: check and add other extensions
//
//        return generator.generate(keyPair.getPrivate(), "SHA256withRSA");
//    }
//
//    private KeyPair generateKeyPair() throws Exception {
//        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
//        generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
//        return generator.generateKeyPair();
//    }

}
