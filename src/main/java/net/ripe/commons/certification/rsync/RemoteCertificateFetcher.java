package net.ripe.commons.certification.rsync;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.util.CertificateRepositoryObjectFactory;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.io.FileUtils;

public class RemoteCertificateFetcher {

    private Rsync rsync;


    public RemoteCertificateFetcher() {
        this.rsync = new Rsync();
    }

    public X509ResourceCertificate getRemoteResourceCertificate(String sourcePath) {
        try {
            return (X509ResourceCertificate) getRemoteObject(sourcePath);
        } catch (ClassCastException e) {
            throw new RemoteCertificateFetcherException("Remote object at: " + sourcePath + "is NOT a X509ResourceCertificate", e);
        }
    }

    public X509Crl getRemoteCrl(String sourcePath) {
        try {
            return (X509Crl) getRemoteObject(sourcePath);
        } catch (ClassCastException e) {
            throw new RemoteCertificateFetcherException("Remote object at: " + sourcePath + "is NOT a X509Crl", e);
        }
    }

    private CertificateRepositoryObject getRemoteObject(String sourcePath) {
        String tempDestinationPath = System.getProperty("java.io.tmpdir") + "/" + UUID.randomUUID();
        File tempDestinationFile = new File(tempDestinationPath);
        try {
            rsync.reset();
            rsync.setSource(sourcePath);

            rsync.setDestination(tempDestinationPath);

            int rc = rsync.execute();
            if (rc == 0) {
                byte[] encoded = FileUtils.readFileToByteArray(tempDestinationFile);
                return CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded);
            }
            return null;
        } catch (IOException e) {
            throw new RemoteCertificateFetcherException("I/O error occured trying to rsync from: " + rsync.getSource() + " to:" + rsync.getDestination(), e);
        } catch (ClassCastException e) {
            throw new RemoteCertificateFetcherException("Remote object is not a resource certificate!", e);
        } finally {
            if (tempDestinationFile.exists()) {
                tempDestinationFile.delete();
            }
        }
    }

    /**
     * Use this for stubbing rsync to test this class..
     */
    void setRsyncClient(Rsync stubbedRsync) {
        this.rsync = stubbedRsync;
    }
}
