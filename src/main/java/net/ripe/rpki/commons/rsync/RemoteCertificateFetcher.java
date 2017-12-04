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
        String tempDestinationPath = ConfigurationUtil.getTempDirectory() + "/rsync-tmp-" + UUID.randomUUID();
        File tempDestinationFile = new File(tempDestinationPath);
        try {
            if (!tempDestinationFile.exists()) {
                tempDestinationFile.getParentFile().mkdir();
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
        }
    }

    /**
     * Use this for stubbing rsync to test this class..
     */
    void setRsyncClient(Rsync stubbedRsync) {
        this.rsync = stubbedRsync;
    }
}
