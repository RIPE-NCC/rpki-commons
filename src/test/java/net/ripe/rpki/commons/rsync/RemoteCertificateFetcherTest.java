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
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509CrlTest;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.Assert.*;


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

                Files.write(encoded, new File(getDestination()));
                return 0;
            } catch (IOException e) {
                e.printStackTrace();
                return 1;
            }
        }
    }
}
