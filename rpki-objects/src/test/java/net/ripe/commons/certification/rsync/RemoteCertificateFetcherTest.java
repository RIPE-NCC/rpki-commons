package net.ripe.commons.certification.rsync;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;

import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.crl.X509CrlTest;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.IpResourceSet;

import org.apache.commons.io.FileUtils;
import org.junit.Before;
import org.junit.Test;


public class RemoteCertificateFetcherTest {

    private RemoteCertificateFetcher subject;

    private static final String RSYNC_SOME_VALID_SOURCE_PATH_CER = "rsync://some.valid/path.cer";
    private static final String RSYNC_SOME_VALID_SOURCE_PATH_CRL = "rsync://some.valid/path.crl";

    private static final X509ResourceCertificate TEST_CERTIFICATE = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(IpResourceSet.ALL_PRIVATE_USE_RESOURCES);
    private static final X509Crl TEST_CRL = X509CrlTest.createCrl();


    @Before
    public void setUp() {
        subject = new RemoteCertificateFetcher();
        subject.setRsyncClient(new StubbedRsync());
    }


    @Test
    public void shouldGetCertificateFromRemoteUri() {
        X509ResourceCertificate actualCertificate = subject.getRemoteResourceCertificate(RSYNC_SOME_VALID_SOURCE_PATH_CER);
        assertNotNull(actualCertificate);
        assertEquals(TEST_CERTIFICATE, actualCertificate);
    }

    @Test
    public void shouldGetCrlFromRemoteUri() {
        X509Crl actualCrl = subject.getRemoteCrl(RSYNC_SOME_VALID_SOURCE_PATH_CRL);
        assertNotNull(actualCrl);
        assertEquals(TEST_CRL, actualCrl);
    }

    private static final class StubbedRsync extends Rsync {

        @Override
        public int execute() {

            try {
                byte[] encoded = null;

                if (getSource().equals(RSYNC_SOME_VALID_SOURCE_PATH_CER)) {
                    encoded = TEST_CERTIFICATE.getEncoded();
                }

                if (getSource().equals(RSYNC_SOME_VALID_SOURCE_PATH_CRL)) {
                    encoded = TEST_CRL.getEncoded();
                }

                FileUtils.writeByteArrayToFile(new File(getDestination()), encoded);
                return 0;
            } catch (IOException e) {
                return 1;
            }
        }
    }
}
