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
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;

import java.math.BigInteger;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * A manifest of files published by a CA certificate.
 * <p/>
 * Use the {@link ManifestCmsBuilder} or {@link ManifestCmsParser} to construct this object.
 */
public class ManifestCms extends RpkiSignedObject {

    public static final int DEFAULT_VERSION = 0;

    public static final ASN1ObjectIdentifier CONTENT_TYPE = new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.26");

    public static final String FILE_HASH_ALGORITHM = CMSSignedDataGenerator.DIGEST_SHA256;

    /**
     * Allowed format of a manifest entry file name.
     */
    private static final Pattern FILE_NAME_PATTERN = Pattern.compile("[a-zA-Z0-9_-]+\\.[a-z]{3}");

    private final Map<String, byte[]> hashes;

    private final ManifestCmsGeneralInfo manifestCmsGeneralInfo;

    ManifestCms(RpkiSignedObjectInfo cmsObjectData, ManifestCmsGeneralInfo manifestCmsGeneralInfo, Map<String, byte[]> hashes) {
        super(cmsObjectData);
        this.manifestCmsGeneralInfo = manifestCmsGeneralInfo;
        this.hashes = hashes;
    }

    public int getVersion() {
        return manifestCmsGeneralInfo.version();
    }

    public BigInteger getNumber() {
        return manifestCmsGeneralInfo.number();
    }

    public String getFileHashAlgorithm() {
        return manifestCmsGeneralInfo.fileHashAlgorithm();
    }

    public Instant getThisUpdateTime() {
        return manifestCmsGeneralInfo.thisUpdateTime();
    }

    public Instant getNextUpdateTime() {
        return manifestCmsGeneralInfo.nextUpdateTime();
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
        // A Manifest matches a set of files when:
        //   * The file names are unique (implied by hashes being a Map),
        //   * The manifest and the set of files contain the same file names, and
        //   * For each file, the hash of the content matches the hash on the manifest.
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
    protected void validateWithCrl(String location, CertificateRepositoryObjectValidationContext context, ValidationOptions options, ValidationResult result, X509Crl crl) {
        result.setLocation(new ValidationLocation(location));
        checkManifestValidityTimes(options, result);
        checkEntries(result);
        super.validateWithCrl(location, context, options, result, crl);
    }

    private void checkEntries(ValidationResult result) {
        List<String> failedEntries = getFileNames().stream()
                .filter(s -> !FILE_NAME_PATTERN.matcher(s).matches())
                .toList();
        result.rejectIfFalse(
                failedEntries.isEmpty(),
                ValidationString.MANIFEST_ENTRY_FILE_NAME_IS_RELATIVE,
                failedEntries.stream().map(StringEscapeUtils::escapeJava).collect(Collectors.joining(", "))
        );
    }

    private void checkManifestValidityTimes(ValidationOptions options, ValidationResult result) {
        var thisUpdateTime = getThisUpdateTime();
        var nextUpdateTime = getNextUpdateTime();

        result.rejectIfFalse(thisUpdateTime.isBefore(nextUpdateTime), ValidationString.MANIFEST_THIS_UPDATE_TIME_BEFORE_NEXT_UPDATE_TIME, thisUpdateTime.toString(), nextUpdateTime.toString());
        result.rejectIfTrue(thisUpdateTime.isAfter(result.now()), ValidationString.MANIFEST_BEFORE_THIS_UPDATE_TIME, thisUpdateTime.toString());

        if (options.isStrictManifestCRLValidityChecks()) {
            boolean postGracePeriod = nextUpdateTime.plus(options.getManifestMaxStalePeriod()).isBefore(result.now());
            if (postGracePeriod) {
                result.error(ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, nextUpdateTime.toString());
            } else {
                result.warnIfTrue(nextUpdateTime.isBefore(result.now()), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, nextUpdateTime.toString());
            }
        } else {
            result.warnIfTrue(nextUpdateTime.isBefore(result.now()), ValidationString.MANIFEST_PAST_NEXT_UPDATE_TIME, nextUpdateTime.toString());
        }

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
        private final byte[] hash;

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
