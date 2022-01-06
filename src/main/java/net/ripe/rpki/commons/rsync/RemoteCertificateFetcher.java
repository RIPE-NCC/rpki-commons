package net.ripe.rpki.commons.rsync;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.ConfigurationUtil;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.io.File;
import java.io.IOException;
import java.util.UUID;

@Deprecated
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
        // ConfigurationUtil does not return the system temp directory but another one
        String tempDestinationPath = ConfigurationUtil.getTempDirectory() + "/rsync-tmp-" + UUID.randomUUID();
        File tempDestinationFile = new File(tempDestinationPath);
        boolean dirCreated = false;
        try {
            if (!tempDestinationFile.exists()) {
                dirCreated = tempDestinationFile.getParentFile().mkdir();
            }
            rsync.reset();
            rsync.setSource(sourcePath);
            rsync.setDestination(tempDestinationPath);

            int rc = rsync.execute();
            if (rc == 0) {
                final byte[] encoded = Files.toByteArray(tempDestinationFile);
                return CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, ValidationResult.withLocation(sourcePath));
            }
            return null;
        } catch (IOException e) {
            throw new RemoteCertificateFetcherException("I/O error occurred trying to rsync from: " + rsync.getSource() + " to:" + rsync.getDestination(), e);
        } catch (ClassCastException e) {
            throw new RemoteCertificateFetcherException("Remote object is not a resource certificate!", e);
        } finally {
            if (tempDestinationFile.exists()) {
                tempDestinationFile.delete();
            }
            if (dirCreated) {
                tempDestinationFile.getParentFile().delete();
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
