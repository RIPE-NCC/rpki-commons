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
package net.ripe.rpki.commons.crypto.util;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.crl.X509Crl.Entry;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import org.bouncycastle.util.encoders.Hex;

import java.io.PrintWriter;
import java.util.Map;
import java.util.SortedSet;

public final class CertificateRepositoryObjectPrinter {

    // Utility class
    private CertificateRepositoryObjectPrinter() {
    }

    public static void print(PrintWriter printWriter, CertificateRepositoryObject cro) {
        if (cro instanceof X509ResourceCertificate) {
            printX509ResourceCertificate(printWriter, (X509ResourceCertificate) cro);
        } else if (cro instanceof ManifestCms) {
            printManifestCms(printWriter, (ManifestCms) cro);
        } else if (cro instanceof RoaCms) {
            printRoaCms(printWriter, (RoaCms) cro);
        } else if (cro instanceof X509Crl) {
            printCrl(printWriter, (X509Crl) cro);
        }
    }


    private static void printX509ResourceCertificate(PrintWriter printWriter, X509ResourceCertificate resourceCertificate) {
        printWriter.println("Object Type: X509Certificate with RFC3779 Internet Resource Extension");
        printWriter.println("Serial: " + resourceCertificate.getSerialNumber());
        printWriter.println("Subject: " + resourceCertificate.getSubject());
        printWriter.println("Not valid before: " + resourceCertificate.getValidityPeriod().getNotValidBefore());
        printWriter.println("Not valid after:  " + resourceCertificate.getValidityPeriod().getNotValidAfter());
        printWriter.println("Resources: " + resourceCertificate.getResources());
    }

    private static void printManifestCms(PrintWriter printWriter, ManifestCms manifest) {
        printWriter.println("Object Type: RPKI Manifest");
        printWriter.println("Signing time: " + manifest.getSigningTime());
        printWriter.println("Version: " + manifest.getVersion());
        printWriter.println("Number: " + manifest.getNumber());
        printWriter.println("This update time: " + manifest.getThisUpdateTime());
        printWriter.println("Next update time: " + manifest.getNextUpdateTime());
        printWriter.println("Authority Key Identifier: " + new String(Hex.encode(manifest.getCertificate().getAuthorityKeyIdentifier())));
        printWriter.println("Filenames and hashes:");
        for (Map.Entry<String, byte[]> fileEntry : manifest.getHashes().entrySet()) {
            printWriter.print("    ");
            printWriter.print(fileEntry.getKey());
            printWriter.print(" ");
            printWriter.println(new String(Hex.encode(fileEntry.getValue())));
        }

    }

    private static void printRoaCms(PrintWriter printWriter, RoaCms roa) {
        printWriter.println("Object Type: Route Origin Authorisation object");
        printWriter.println("Signing time: " + roa.getSigningTime());
        printWriter.println("ASN: " + roa.getAsn());
        printWriter.println("Prefixes:");
        for (RoaPrefix prefix : roa.getPrefixes()) {
            printWriter.print("    " + prefix.getPrefix());
            if (prefix.getMaximumLength() != null) {
                printWriter.println(" [" + prefix.getMaximumLength() + "]");
            } else {
                printWriter.println();
            }
        }
    }

    private static void printCrl(PrintWriter printWriter, X509Crl crl) {
        printWriter.println("Object Type: Certificate Revocation List");
        printWriter.println("CRL version: " + crl.getVersion());
        printWriter.println("Issuer: " + crl.getIssuer());
        printWriter.println("Authority key identifier: " + KeyPairUtil.base64UrlEncode(crl.getAuthorityKeyIdentifier()));
        printWriter.println("Number: " + crl.getNumber());
        printWriter.println("This update time: " + crl.getThisUpdateTime());
        printWriter.println("Next update time: " + crl.getNextUpdateTime());
        printWriter.println("Revoked certificates serial numbers and revocation time:");
        SortedSet<Entry> revokedCertificates = crl.getRevokedCertificates();
        for (Entry entry : revokedCertificates) {
            printWriter.print("    ");
            printWriter.print(entry.getSerialNumber());
            printWriter.print(" ");
            printWriter.println(entry.getRevocationDateTime());
        }
    }

}
