/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
package net.ripe.commons.certification.cms.manifest;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.RpkiSignedObject;
import net.ripe.commons.certification.cms.RpkiSignedObjectInfo;
import net.ripe.commons.certification.crl.CrlLocator;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.util.Specification;
import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationOptions;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.ValidationString;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.NullOutputStream;
import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.joda.time.DateTime;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.util.Arrays;
import java.util.Map;
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

    private Map<String, byte[]> files;

    private ManifestCmsGeneralInfo manifestCmsGeneralInfo;

    ManifestCms(RpkiSignedObjectInfo cmsObjectData, ManifestCmsGeneralInfo manifestCmsGeneralInfo, Map<String, byte[]> files) {
        super(cmsObjectData);
        this.manifestCmsGeneralInfo = manifestCmsGeneralInfo;
        this.files = files;
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
        return files.size();
    }

    public boolean containsFile(String fileName) {
        return files.containsKey(fileName);
    }

    public Map<String, byte[]> getFiles() {
        return files;
    }

    public Set<String> getFileNames() {
        return files.keySet();
    }

    @Override
    public URI getCrlUri() {
        return getCertificate().findFirstRsyncCrlDistributionPoint();
    }

    @Override
    public URI getParentCertificateUri() {
        return getCertificate().getParentCertificateUri();
    }
    
    @Override
    public void validate(String location, CertificateRepositoryObjectValidationContext context, CrlLocator crlLocator, ValidationOptions options, ValidationResult result) {
        ValidationLocation savedCurrentLocation = result.getCurrentLocation();
        result.setLocation(new ValidationLocation(getCrlUri()));

        X509Crl crl = crlLocator.getCrl(getCrlUri(), context, result);

        result.setLocation(savedCurrentLocation);
        result.rejectIfNull(crl, ValidationString.OBJECTS_CRL_VALID, getCrlUri().toString());
        if (crl == null) {
            return;
        }

        result.setLocation(new ValidationLocation(location));
        checkManifestAndEeCertificateValidityTimes(options, result);
        ManifestCmsEeCertificateValidator validator = new ManifestCmsEeCertificateValidator(options, result, context.getCertificate(), crl, context.getResources());
        validator.validate(location, getCertificate());
    }
    

    private void checkManifestAndEeCertificateValidityTimes(ValidationOptions options, ValidationResult result) {
		ValidityPeriod certificateValidity = getCertificate().getValidityPeriod();
		result.warnIfFalse(certificateValidity.getNotValidBefore().equals(getThisUpdateTime()), ValidationString.MANIFEST_VALIDITY_TIMES_INCONSISTENT);
		result.warnIfFalse(certificateValidity.getNotValidAfter().equals(getNextUpdateTime()), ValidationString.MANIFEST_VALIDITY_TIMES_INCONSISTENT);

        DateTime now = new DateTime();
        DateTime nextUpdateTime = getNextUpdateTime();

        if (now.isAfter(nextUpdateTime)) {
            if (nextUpdateTime.plusDays(options.getMaxStaleDays()).isAfter(now)) {
                 result.warnIfTrue(true, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME);
            } else {
                result.rejectIfTrue(true, ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME);
            }
        }


	}

	/**
     * @deprecated use {@link #verifyFileContents(String, byte[])} or {@link #getFileContentSpecification(String)}.
     */
    @Deprecated
    public byte[] getHash(String fileName) {
        return files.get(fileName);
    }

    public boolean verifyFileContents(String fileName, byte[] contents) {
        return getFileContentSpecification(fileName).isSatisfiedBy(contents);
    }

    public FileContentSpecification getFileContentSpecification(String fileName) {
        Validate.isTrue(containsFile(fileName));
        return new FileContentSpecification(getHash(fileName));
    }

    public static ManifestCms parseDerEncoded(byte[] encoded) {
        ManifestCmsParser parser = new ManifestCmsParser();
        parser.parse("<null>", encoded);
        return parser.getManifestCms();
    }

    public static byte[] hashContents(byte[] contents) {
        NullOutputStream fileOut = null;
        DigestOutputStream digestOut = null;
        try {
            Digest digest = new SHA256Digest();
            fileOut = new NullOutputStream();
            digestOut = new DigestOutputStream(fileOut, digest);

            digestOut.write(contents);
            digestOut.flush();

            byte[] digestValue = new byte[digest.getDigestSize()];
            digest.doFinal(digestValue, 0);
            return digestValue;
        } catch (IOException e) {
            throw new ManifestCmsException(e);
        } finally {
            if (digestOut != null) {
                IOUtils.closeQuietly(digestOut);
            } else if (fileOut != null) {
                IOUtils.closeQuietly(fileOut);
            }
        }
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
