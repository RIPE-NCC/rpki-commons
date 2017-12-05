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
package net.ripe.rpki.commons.crypto.cms.manifest;

import net.ripe.rpki.commons.crypto.cms.RpkiSignedObject;
import net.ripe.rpki.commons.crypto.cms.RpkiSignedObjectInfo;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationOptions;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.ValidationString;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.commons.validation.objectvalidators.ResourceValidatorFactory;
import net.ripe.rpki.commons.validation.objectvalidators.X509ResourceCertificateParentChildValidator;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.joda.time.DateTime;

import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * A manifest of files published by a CA certificate.
 * <p/>
 * Use the {@link ManifestCmsBuilder} or {@link ManifestCmsParser} to construct this object.
 */
public class ManifestCms extends RpkiSignedObject {

    private static final long serialVersionUID = 1L;

    public static final int DEFAULT_VERSION = 0;

    public static final String CONTENT_TYPE_OID = "1.2.840.113549.1.9.16.1.26";

    public static final String FILE_HASH_ALGORITHM = CMSSignedDataGenerator.DIGEST_SHA256;

    private Map<String, byte[]> hashes;

    private ManifestCmsGeneralInfo manifestCmsGeneralInfo;

    ManifestCms(RpkiSignedObjectInfo cmsObjectData, ManifestCmsGeneralInfo manifestCmsGeneralInfo, Map<String, byte[]> hashes) {
        super(cmsObjectData);
        this.manifestCmsGeneralInfo = manifestCmsGeneralInfo;
        this.hashes = hashes;
    }

    public int getVersion() {
        return manifestCmsGeneralInfo.getVersion();
    }

    public BigInteger getNumber() {
        return manifestCmsGeneralInfo.getNumber();
    }

    public String getFileHashAlgorithm() {
        return manifestCmsGeneralInfo.getFileHashAlgorithm();
    }

    public DateTime getThisUpdateTime() {
        return manifestCmsGeneralInfo.getThisUpdateTime();
    }

    public DateTime getNextUpdateTime() {
        return manifestCmsGeneralInfo.getNextUpdateTime();
    }

    public int size() {
        return hashes.size();
    }

    public boolean containsFile(String fileName) {
        return hashes.containsKey(fileName);
    }

    public Map<String, byte[]> getHashes() {
        return hashes;
    }

    public Map<String, byte[]> getFiles() {
        return getHashes();
    }

    public boolean matchesFiles(Map<String, byte[]> filesToMatch) {

        if (hashes.keySet().equals(filesToMatch.keySet())) {
            for (Entry<String, byte[]> entry : hashes.entrySet()) {
                String fileName = entry.getKey();
                byte[] contentToMatch = filesToMatch.get(fileName);
                if (!verifyFileContents(fileName, contentToMatch)) {
                    return false;
                }
            }
            return true;
        } else {
            return false;
        }
    }

    public Set<String> getFileNames() {
        return hashes.keySet();
    }

    @Override
    public URI getCrlUri() {
        return getCertificate().findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }

    protected void validateWithCrl(String location, CertificateRepositoryObjectValidationContext context, ValidationOptions options, ValidationResult result, X509Crl crl) {
        result.setLocation(new ValidationLocation(location));
        checkManifestValidityTimes(options, result);
        X509ResourceCertificateParentChildValidator validator = ResourceValidatorFactory.getX509ResourceCertificateStrictValidator(context, options, result, crl);
        validator.validate(location, getCertificate());
    }


    private void checkManifestValidityTimes(ValidationOptions options, ValidationResult result) {
        DateTime now = new DateTime();
        DateTime nextUpdateTime = getNextUpdateTime();
        result.warnIfTrue(now.isAfter(nextUpdateTime), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME);
    }

    /**
     * @deprecated use {@link #verifyFileContents(String, byte[])} or {@link #getFileContentSpecification(String)}.
     */
    @Deprecated
    public byte[] getHash(String fileName) {
        return hashes.get(fileName);
    }

    public boolean verifyFileContents(String fileName, byte[] contents) {
        return getFileContentSpecification(fileName).isSatisfiedBy(contents);
    }

    public FileContentSpecification getFileContentSpecification(String fileName) {
        Validate.isTrue(containsFile(fileName));
        return new FileContentSpecification(getHash(fileName));
    }

    public static byte[] hashContents(byte[] contents) {
        final Digest digest = new SHA256Digest();
        digest.update(contents, 0, contents.length);
        final byte[] digestValue = new byte[digest.getDigestSize()];
        digest.doFinal(digestValue, 0);
        return digestValue;
    }

    public static class FileContentSpecification implements Specification<byte[]> {
        private byte[] hash;

        public FileContentSpecification(byte[] hash) {
            this.hash = Arrays.copyOf(hash, hash.length);
        }

        public byte[] getHash() {
            return Arrays.copyOf(hash, hash.length);
        }

        @Override
        public boolean isSatisfiedBy(byte[] contents) {
            return Arrays.equals(hash, hashContents(contents));
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = 1;
            result = prime * result + Arrays.hashCode(hash);
            return result;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final FileContentSpecification other = (FileContentSpecification) obj;
            return Arrays.equals(hash, other.hash);
        }

        @Override
        public String toString() {
            return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE).append("hash", hash).toString();
        }
    }

}
