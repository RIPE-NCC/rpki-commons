package net.ripe.commons.certification.validation;

public final class ValidationString {

    private ValidationString() {
        //Utility classes should not have a public or default constructor.
    }


    //////////////////////////////////////////////
    // CERTIFICATE REPOSITORY OBJECT VALIDATION
    //////////////////////////////////////////////

    // generic
    public static final String OBJECTS_CRL_VALID = "objects.crl.valid";
    public static final String UNKNOWN_OBJECT_TYPE = "unknown.object.type";

	//certificate (validator)
	public static final String CERT_CHAIN_LENGTH = "cert.chain.length";
	public static final String CERT_CHAIN_COMPLETE = "cert.chain.complete";
	public static final String CERT_CHAIN_CIRCULAR_REFERENCE = "cert.chain.circular.reference";
	public static final String ISSUER_IS_CA = "cert.issuer.is.ca";
	public static final String SIGNATURE_VALID = "cert.signature";
	public static final String NOT_VALID_BEFORE = "cert.not.valid.before";
	public static final String NOT_VALID_AFTER = "cert.not.valid.after";
	public static final String RESOURCE_RANGE = "cert.resource.range.is.valid";
	public static final String PREV_SUBJECT_EQ_ISSUER = "cert.issuer.eq.prev.subject";
	public static final String KEY_USAGE_EXT_PRESENT = "cert.key.usage.extension.present";
	public static final String KEY_CERT_SIGN = "cert.key.cert.sign";
	public static final String SKI_PRESENT = "cert.ski.present";
	public static final String AKI_PRESENT = "cert.aki.present";
	public static final String PREV_SKI_EQ_AKI = "cert.aki.eq.prev.ski";
	public static final String CERT_REVOKED = "cert.revoked";
	public static final String ROOT_IS_TA = "cert.root.is.ta";
	public static final String CERT_AIA_NOT_POINTING_TO_CERT = "cert.aia.no.certificate";
	public static final String DIFFERENT_CERTIFICATE_TYPES = "cert.types.different";
	public static final String CERTIFICATE_SIGNATURE_ALGORITHM = "cert.signature.algorithm";

	// CRL stuff
	public static final String CRL_PARSED = "crl.parsed";
	public static final String CRL_SIGNATURE_VALID = "cert.crl.signature";
	public static final String CRL_REQUIRED= "crl.required";
    public static final String CRL_NEXT_UPDATE_BEFORE_NOW = "crl.next.update.before.now";
    public static final String CRL_MANIFEST_VALID = "crl.manifest.valid";

	//certificate (parser)
	public static final String CERTIFICATE_PARSED = "cert.parsed";
	public static final String CRITICAL_EXT_PRESENT = "cert.critical.exts.present";
	public static final String POLICY_EXT_CRITICAL = "cert.policy.ext.critical";
	public static final String POLICY_EXT_VALUE = "cert.policy.ext.value";
	public static final String SINGLE_CERT_POLICY = "cert.single.cert.policy";
	public static final String POLICY_QUALIFIER = "cert.policy.qualifier.present";
	public static final String POLICY_ID_PRESENT = "cert.policy.id.present";
	public static final String POLICY_ID_VERSION = "cert.policy.id.version";
	public static final String POLICY_VALIDATION = "cert.policy.validation";
	public static final String RESOURCE_EXT_PRESENT = "cert.resource.ext.present";
	public static final String AS_OR_IP_RESOURCE_PRESENT = "cert.as.or.ip.resource.present";
	public static final String PARTIAL_INHERITANCE = "cert.partial.resource.inheritance";

	//cms object
	public static final String CMS_DATA_PARSING = "cms.signed.data.parsing";
	public static final String CMS_SIGNED_DATA_VERSION = "cms.signed.data.version";
	public static final String CMS_SIGNED_DATA_DIGEST_ALGORITHM = "cms.signed.data.digest.algorithm";
	public static final String CMS_CONTENT_TYPE = "cms.content.type";
	public static final String DECODE_CONTENT = "cms.decode.content";
	public static final String ONLY_ONE_SIGNED_OBJECT = "cms.only.one.signed.object";
	public static final String CMS_CONTENT_PARSING = "cms.content.parsing";
	public static final String GET_CERTS_AND_CRLS = "cms.get.certs.and.crls";
	public static final String ONLY_ONE_EE_CERT_ALLOWED = "cms.only.one.ee.cert";
	public static final String CERT_IS_X509CERT = "cms.cert.is.x509";
	public static final String CERT_IS_EE_CERT = "cms.cert.is.ee.cert";
	public static final String ONLY_ONE_CRL_ALLOWED = "cms.only.one.crl";
	public static final String CRL_IS_X509CRL = "cms.crl.is.x509";
	public static final String CERT_HAS_SKI = "cms.cert.has.ski";
	public static final String GET_SIGNER_INFO = "cms.signature.signer.info";
	public static final String ONLY_ONE_SIGNER = "cms.signature.has.one.signer";
	public static final String CMS_SIGNER_INFO_VERSION = "cms.signer.info.version";
	public static final String CMS_SIGNER_INFO_DIGEST_ALGORITHM = "cms.signer.info.digest.algorithm";
	public static final String CMS_SIGNER_INFO_SKI = "cms.signer.info.ski";
	public static final String CMS_SIGNER_INFO_SKI_ONLY = "cms.signer.info.ski.only";
	public static final String ENCRYPTION_ALGORITHM = "cms.encryption.algorithm";
	public static final String SIGNED_ATTRS_PRESENT = "cms.signed.attrs.present";
	public static final String CONTENT_TYPE_ATTR_PRESENT = "cms.content.type.attr.present";
	public static final String CONTENT_TYPE_VALUE_COUNT = "cms.content.type.value.count";
	public static final String CONTENT_TYPE_VALUE = "cms.content.type.value";
	public static final String MSG_DIGEST_ATTR_PRESENT = "cms.msg.digest.attr.present";
	public static final String MSG_DIGEST_VALUE_COUNT = "cms.msg.digest.value.count";
	public static final String SIGNING_TIME_ATTR_PRESENT = "cms.signing.time.attr.present";
	public static final String ONLY_ONE_SIGNING_TIME_ATTR = "cms.only.one.signing.time.attr";
	public static final String SIGNER_ID_MATCH = "cms.signer.id.match.cert";
	public static final String SIGNATURE_VERIFICATION = "cms.signature";
	public static final String UNSIGNED_ATTRS_OMITTED = "cms.unsigned.attrs.omitted";

	//roacms
	public static final String ROA_CONTENT_TYPE = "roa.content.type";
	public static final String ROA_RESOURCES = "roa.resources";
	public static final String ASN_AND_PREFIXES_IN_DER_SEQ = "roa.seq.has.asn.and.prefixes";
	public static final String ROA_PREFIX_LIST = "roa.prefix.list.not.empty";
	public static final String ADDR_FAMILY_AND_ADDR_IN_DER_SEQ = "roa.seq.has.addr.family.and.addressed";
	public static final String ADDR_FAMILY = "roa.addr.family.valid";
	public static final String PREFIX_IN_ADDR_FAMILY = "roa.addr.family.contains.prefix";
	public static final String PREFIX_LENGTH = "roa.prefix.length";

	//manifest
	public static final String MANIFEST_CONTENT_TYPE = "mf.content.type";
	public static final String MANIFEST_CONTENT_SIZE = "mf.content.size";
	public static final String MANIFEST_CONTENT_STRUCTURE = "mf.content.structure";
	public static final String MANIFEST_TIME_FORMAT = "mf.time.format";
    public static final String MANIFEST_FILE_HASH_ALGORITHM = "mf.file.hash.algorithm";
	public static final String MANIFEST_DECODE_FILELIST = "mf.decode.filelist";
	public static final String MANIFEST_RESOURCE_INHERIT = "mf.resource.inherit";

	//validator
	public static final String VALIDATOR_URI_SAFETY = "validator.uri.safety";
	public static final String VALIDATOR_URI_RSYNC_SCHEME = "validator.uri.rsync.scheme";
	public static final String VALIDATOR_URI_HOST = "validator.uri.host";
	public static final String VALIDATOR_URI_PATH = "validator.uri.path";
	public static final String VALIDATOR_FILE_CONTENT = "validator.file.content";
	public static final String VALIDATOR_READ_FILE = "validator.read.file";
	public static final String VALIDATOR_RSYNC_COMMAND = "validator.rsync.command";
	public static final String VALIDATOR_FETCHED_OBJECT_IS_MANIFEST = "validator.fetched.object.is.manifest";
	public static final String VALIDATOR_FETCHED_OBJECT_IS_CRL = "validator.fetched.object.is.crl";
	public static final String VALIDATOR_MANIFEST_DOES_NOT_CONTAIN_FILE = "validator.manifest.does.not.contain.file";


	////////////////////////////////
	// FIELD VALIDATION
	////////////////////////////////

	// Roa Specification
    public static final String ROA_SPECIFICATION_NAME_REQUIRED = "roaSpecification.nameRequired";
    public static final String ROA_SPECIFICATION_NAME_ALREADY_EXISTS = "roaSpecification.nameExists";
    public static final String ROA_SPECIFICATION_NAME_PATTERN = "roaSpecification.namePattern";
    public static final String ROA_SPECIFICATION_NAME_LENGTH = "roaSpecification.nameLength";

    public static final String ROA_SPECIFICATION_ASN_REQUIRED = "roaSpecification.asnRequired";
    public static final String ROA_SPECIFICATION_ASN_VALID = "roaSpecification.asnValid";

    public static final String ROA_SPECIFICATION_DATE_TIME_REQUIRED = "roaSpecification.dateTimeRequired";
    public static final String ROA_SPECIFICATION_DATE_TIME_VALID = "roaSpecification.dateTimeValid";

    public static final String ROA_SPECIFICATION_PREFIX_REQUIRED = "roaSpecification.prefixRequired";
    public static final String ROA_SPECIFICATION_PREFIX_VALID = "roaSpecification.illegalPrefix";
    public static final String ROA_SPECIFICATION_PREFIX_NOT_HELD_BY_CA = "roaSpecification.notOwnerOfResource";

    public static final String ROA_SPECIFICATION_MAX_LENGTH_VALID = "roaSpecification.invalidMaximumLength";
}
