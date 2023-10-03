package net.ripe.rpki.commons.validation;

public final class ValidationString {

    private ValidationString() {
        //Utility classes should not have a public or default constructor.
    }


    //////////////////////////////////////////////
    // CERTIFICATE REPOSITORY OBJECT VALIDATION
    //////////////////////////////////////////////

    // generic
    public static final String OBJECTS_GENERAL_PARSING = "objects.general.parsing";
    public static final String OBJECTS_CRL_VALID = "objects.crl.valid";
    public static final String KNOWN_OBJECT_TYPE = "known.object.type";

    // Trust anchor
    public static final String TRUST_ANCHOR_PUBLIC_KEY_MATCH = "trust.anchor.public.key.match";

    //certificate (validator)
    public static final String CERT_CHAIN_LENGTH = "cert.chain.length";
    public static final String CERT_CHAIN_COMPLETE = "cert.chain.complete";
    public static final String CERT_CHAIN_CIRCULAR_REFERENCE = "cert.chain.circular.reference";
    public static final String ISSUER_IS_CA = "cert.issuer.is.ca";
    public static final String SIGNATURE_VALID = "cert.signature";
    public static final String NOT_VALID_BEFORE = "cert.not.valid.before";
    public static final String NOT_VALID_AFTER = "cert.not.valid.after";
    public static final String RESOURCE_RANGE = "cert.resource.range.is.valid";
    public static final String ROOT_INHERITS_RESOURCES = "cert.root.resource.uses.inherit";
    public static final String PREV_SUBJECT_EQ_ISSUER = "cert.issuer.eq.prev.subject";
    public static final String KEY_USAGE_EXT_PRESENT = "cert.key.usage.extension.present";
    public static final String KEY_USAGE_EXT_CRITICAL = "cert.key.usage.critical";
    public static final String KEY_USAGE_INVALID = "cert.key.usage.invalid";
    public static final String PUBLIC_KEY_CERT_ALGORITHM = "cert.public.key.algorithm";
    public static final String PUBLIC_KEY_CERT_SIZE = "cert.public.key.size";
    public static final String KEY_CERT_SIGN = "cert.key.cert.sign";
    public static final String CRL_SIGN = "cert.crl.sign";
    public static final String DIG_SIGN = "cert.dig.sign";
    public static final String SKI_PRESENT = "cert.ski.present";
    public static final String AKI_PRESENT = "cert.aki.present";
    public static final String PREV_SKI_EQ_AKI = "cert.aki.eq.prev.ski";
    public static final String CERT_NOT_REVOKED = "cert.not.revoked";
    public static final String ROOT_IS_TA = "cert.root.is.ta";
    public static final String CERT_AIA_NOT_POINTING_TO_CERT = "cert.aia.no.certificate";
    public static final String DIFFERENT_CERTIFICATE_TYPES = "cert.types.different";
    public static final String CERTIFICATE_SIGNATURE_ALGORITHM = "cert.signature.algorithm";

    // CRL stuff
    public static final String CRL_PARSED = "crl.parsed";
    public static final String CRL_SIGNATURE_VALID = "cert.crl.signature";
    public static final String CRL_REQUIRED = "crl.required";
    public static final String CRL_NEXT_UPDATE_BEFORE_NOW = "crl.next.update.before.now";
    public static final String CRL_THIS_UPDATE_AFTER_NOW = "crl.this.update.after.now";
    public static final String CRL_MANIFEST_VALID = "crl.manifest.valid";
    public static final String CRL_AKI_MISMATCH = "crl.aki.mismatch";

    //certificate (parser)
    public static final String CERTIFICATE_PARSED = "cert.parsed";
    public static final String CRLDP_PRESENT = "cert.crldp.present";
    public static final String CRLDP_OMITTED = "cert.crldp.omitted";
    public static final String CRLDP_EXTENSION_PARSED = "cert.crldp.ext.parsed";
    public static final String CRLDP_ISSUER_OMITTED = "cert.crldp.issuer.omitted";
    public static final String CRLDP_REASONS_OMITTED = "cert.crldp.reasons.omitted";
    public static final String CRLDP_TYPE_FULL_NAME = "cert.crldp.type.full.name";
    public static final String CRLDP_NAME_IS_A_URI = "cert.crldp.name.is.a.uri";
    public static final String CRLDP_URI_SYNTAX = "cert.crldp.uri.syntax";
    public static final String CRLDP_RSYNC_URI_PRESENT = "cert.crldp.rsync.uri.present";
    public static final String CRITICAL_EXT_PRESENT = "cert.critical.exts.present";
    public static final String NON_CRITICAL_EXT_PRESENT = "cert.non.critical.exts.present";
    public static final String POLICY_EXT_CRITICAL = "cert.policy.ext.critical";
    public static final String POLICY_EXT_VALUE = "cert.policy.ext.value";
    public static final String SINGLE_CERT_POLICY = "cert.single.cert.policy";
    public static final String POLICY_QUALIFIER = "cert.policy.qualifier.present";
    public static final String POLICY_ID_PRESENT = "cert.policy.id.present";
    public static final String POLICY_ID_VERSION = "cert.policy.id.version";
    public static final String POLICY_VALIDATION = "cert.policy.validation";
    public static final String POLICY_QUALIFIER_NUMBER = "cert.policy.qualifiers.number";
    public static final String POLICY_QUALIFIER_TYPE = "cert.policy.qualifiers.qualifierid";
    public static final String RESOURCE_EXT_PRESENT = "cert.resource.ext.present";
    public static final String RESOURCE_EXT_NOT_PRESENT = "cert.resource.ext.not.present";
    public static final String IP_RESOURCE_PRESENT = "cert.ip.resource.present";
    public static final String AS_RESOURCE_PRESENT = "cert.as.resource.present";
    public static final String AS_OR_IP_RESOURCE_PRESENT = "cert.as.or.ip.resource.present";
    public static final String CERT_ISSUER_CORRECT = "cert.issuer.correct";
    public static final String CERT_SUBJECT_CORRECT = "cert.subject.correct";
    public static final String CERT_NO_SUBJECT_PK_INFO = "cert.subj.pk.not.present";

    // SIA
    public static final String CERT_SIA_NON_CRITICAL_EXTENSION = "cert.sia.non.critical.extension";
    public static final String CERT_SIA_IS_PRESENT = "cert.sia.present";
    public static final String CERT_SIA_PARSED = "cert.sia.parsed";
    public static final String CERT_SIA_URI_SYNTAX = "cert.sia.uri.syntax";
    public static final String CERT_SIA_CA_REPOSITORY_URI_PRESENT = "cert.sia.ca.repository.uri.present";
    public static final String CERT_SIA_CA_REPOSITORY_RSYNC_URI_PRESENT = "cert.sia.ca.repository.rsync.uri.present";
    public static final String CERT_SIA_MANIFEST_URI_PRESENT = "cert.sia.manifest.uri.present";
    public static final String CERT_SIA_SIGNED_OBJECT_URI_PRESENT = "cert.sia.signed.object.uri.present";
    public static final String CERT_SIA_RRDP_NOTIFY_URI_HTTPS = "cert.sia.rrdp.notify.uri.https";
    public static final String CERT_SIA_EE_CERTIFICATE_OTHER_ACCESS_METHODS = "cert.sia.ee.certificate.other.access.methods";

    // router certificate
    public static final String BGPSEC_EXT_PRESENT = "cert.bgpsec.ext.present";

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
    public static final String CMS_NO_CRL_ALLOWED = "cms.no.crl";
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
    public static final String SIGNED_ATTRS_CORRECT = "cms.signed.attrs.correct";
    public static final String CONTENT_TYPE_ATTR_PRESENT = "cms.content.type.attr.present";
    public static final String CONTENT_TYPE_VALUE_COUNT = "cms.content.type.value.count";
    public static final String CONTENT_TYPE_VALUE = "cms.content.type.value";
    public static final String MSG_DIGEST_ATTR_PRESENT = "cms.msg.digest.attr.present";
    public static final String MSG_DIGEST_VALUE_COUNT = "cms.msg.digest.value.count";
    public static final String SIGNING_TIME_ATTR_PRESENT = "cms.signing.time.attr.present";
    public static final String SIGNING_TIME_ATTR_ONE_VALUE = "cms.signing.time.attr.one.value";
    public static final String ONLY_ONE_SIGNING_TIME_ATTR = "cms.only.one.signing.time.attr";
    public static final String ONLY_ONE_BINARY_SIGNING_TIME_ATTR = "cms.only.one.binary.signing.time.attr";
    public static final String SIGNING_TIME_MUST_EQUAL_BINARY_SIGNING_TIME = "cms.signing.time.must.equal.binary.signing.time";
    public static final String SIGNER_ID_MATCH = "cms.signer.id.match.cert";
    public static final String SIGNATURE_VERIFICATION = "cms.signature";
    public static final String UNSIGNED_ATTRS_OMITTED = "cms.unsigned.attrs.omitted";

    // provisioning CMS payload
    public static final String VALID_PAYLOAD_TYPE = "provisioning.valid.payloadtype";
    public static final String FOUND_PAYLOAD_TYPE = "provisioning.found.payloadtype";
    public static final String VALID_PAYLOAD_VERSION = "provisioning.valid.payloadversion";
    public static final String SIGNING_TIME_GREATER_OR_EQUAL = "provisioning.signing.time.greater.equal";

    //roacms
    public static final String ROA_CONTENT_TYPE = "roa.content.type";
    public static final String ROA_CONTENT_STRUCTURE = "roa.content.structure";
    public static final String ROA_RESOURCES = "roa.resources";
    public static final String ASN_AND_PREFIXES_IN_DER_SEQ = "roa.seq.has.asn.and.prefixes";
    public static final String ROA_ATTESTATION_VERSION = "roa.attestation.version";
    public static final String ROA_PREFIX_LIST = "roa.prefix.list.not.empty";
    public static final String ADDR_FAMILY_AND_ADDR_IN_DER_SEQ = "roa.seq.has.addr.family.and.addressed";
    public static final String ADDR_FAMILY = "roa.addr.family.valid";
    public static final String PREFIX_IN_ADDR_FAMILY = "roa.addr.family.contains.prefix";
    public static final String PREFIX_LENGTH = "roa.prefix.length";

    //manifest
    public static final String MANIFEST_CONTENT_TYPE = "mf.content.type";
    public static final String MANIFEST_CONTENT_STRUCTURE = "mf.content.structure";
    public static final String MANIFEST_TIME_FORMAT = "mf.time.format";
    public static final String MANIFEST_FILE_HASH_ALGORITHM = "mf.file.hash.algorithm";
    public static final String MANIFEST_DECODE_FILELIST = "mf.decode.filelist";
    public static final String MANIFEST_RESOURCE_INHERIT = "mf.resource.inherit";
    public static final String MANIFEST_BEFORE_THIS_UPDATE_TIME = "mf.before.this.update";
    public static final String MANIFEST_PAST_NEXT_UPDATE_TIME = "mf.past.next.update";
    public static final String MANIFEST_THIS_UPDATE_TIME_BEFORE_NEXT_UPDATE_TIME = "mf.this.update.before.next.update";
    public static final String MANIFEST_ENTRY_FILE_NAME_IS_RELATIVE = "mf.entry.file.name.is.relative";

    //ghostbusters
    public static final String GHOSTBUSTERS_RECORD_CONTENT_TYPE = "ghostbusters.record.content.type";
    public static final String GHOSTBUSTERS_RECORD_SINGLE_VCARD = "ghostbusters.record.single.vcard";
    public static final String GHOSTBUSTERS_RECORD_VCARD_VERSION = "ghostbusters.record.vcard.version";
    public static final String GHOSTBUSTERS_RECORD_FN_PRESENT = "ghostbusters.record.fn.present";
    public static final String GHOSTBUSTERS_RECORD_ADR_TEL_OR_EMAIL_PRESENT = "ghostbusters.record.adr.tel.or.email.present";
    public static final String GHOSTBUSTERS_RECORD_SUPPORTED_PROPERTY = "ghostbusters.record.supported.property";

    // ASPA
    public static final String ASPA_CONTENT_TYPE = "aspa.content.type";
    public static final String ASPA_CONTENT_STRUCTURE = "aspa.content.structure";
    public static final String ASPA_VERSION = "aspa.version";
    public static final String ASPA_CUSTOMER_ASN_PRESENT = "aspa.customer.asn.present";
    public static final String ASPA_PROVIDER_AS_SEQUENCE_SIZE = "aspa.provider.as.sequence.size";

    public static final String ASPA_CUSTOMER_ASN_NOT_IN_PROVIDER_ASNS = "aspa.customer.asn.ne.provider.asn";
    public static final String ASPA_CUSTOMER_ASN_CERTIFIED = "aspa.customer.asn.certified";
    public static final String ASPA_PROVIDER_AS_SET_NOT_EMPTY = "aspa.provider.as.set.not.empty";

    public static final String ASPA_PROVIDER_AS_SET_VALID = "aspa.provider.as.set.valid";

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
    public static final String VALIDATOR_MANIFEST_CRL_URI_MISMATCH = "validator.manifest.crl.uri.mismatch";
    public static final String VALIDATOR_MANIFEST_FILE_NOT_FOUND_BY_AKI = "validator.manifest.file.not.found.by.aki";
    public static final String VALIDATOR_MANIFEST_HASH_MISMATCH = "validator.manifest.hash.mismatch";
    public static final String VALIDATOR_MANIFEST_URI_MISMATCH = "validator.manifest.uri.mismatch";
    public static final String VALIDATOR_OBJECT_PROCESSING_EXCEPTION = "validator.object.processing.exception";
    public static final String VALIDATOR_MANIFEST_LOCATION_MISMATCH = "validator.manifest.location.mismatch";
    public static final String VALIDATOR_MANIFEST_IS_INVALID = "validator.manifest.is.invalid";
    public static final String VALIDATOR_CA_SHOULD_HAVE_MANIFEST = "validator.ca.should.have.manifest";
    public static final String VALIDATOR_ROOT_CERTIFICATE_INCLUDED_IN_MANIFEST = "validator.root.certificate.included.in.manifest";
    public static final String VALIDATOR_CIRCULAR_REFERENCE = "validator.circular.reference";

    public static final String VALIDATOR_RPKI_REPOSITORY_PENDING = "validator.rpki.repository.pending";
    public static final String VALIDATOR_TRUST_ANCHOR_CERTIFICATE_AVAILABLE = "validator.trust.anchor.certificate.available";
    public static final String VALIDATOR_TRUST_ANCHOR_CERTIFICATE_RRDP_NOTIFY_URI_OR_REPOSITORY_URI_PRESENT = "validator.trust.anchor.certificate.rrdp.notify.uri.or.repository.uri.present";
    public static final String VALIDATOR_MANIFEST_CONTAINS_ONE_CRL_ENTRY = "validator.manifest.contains.one.crl.entry";
    public static final String VALIDATOR_CRL_FOUND = "validator.crl.found";
    public static final String VALIDATOR_RPKI_OBJECT_HASH_MATCHES = "validator.rpki.object.hash.matches";
    public static final String VALIDATOR_MANIFEST_ENTRY_HASH_MATCHES = "validator.manifest.entry.hash.matches";
    public static final String VALIDATOR_MANIFEST_ENTRY_FOUND = "validator.manifest.entry.found";
    public static final String VALIDATOR_OLD_LOCAL_MANIFEST_REPOSITORY_FAILED = "validator.old.local.manifest.repository.failed";
    public static final String VALIDATOR_NO_LOCAL_MANIFEST_NO_MANIFEST_IN_REPOSITORY = "validator.no.local.manifest.no.manifest.in.repository";
    public static final String VALIDATOR_NO_MANIFEST_REPOSITORY_FAILED = "validator.no.manifest.repository.failed";

    // Problems with repository
    public static final String VALIDATOR_REPOSITORY_INCOMPLETE = "validator.repository.incomplete";
    public static final String VALIDATOR_REPOSITORY_INCONSISTENT = "validator.repository.inconsistent";
    public static final String VALIDATOR_REPOSITORY_UNKNOWN = "validator.repository.unknown";
    public static final String VALIDATOR_REPOSITORY_OBJECT_NOT_IN_CACHE = "validator.repository.object.not.in.cache";
    public static final String VALIDATOR_REPOSITORY_OBJECT_NOT_FOUND = "validator.repository.object.not.found";
    public static final String VALIDATOR_REPOSITORY_NOT_AT_EXPECTED_LOCATION = "validator.repository.object.not.at.expected.location";
    public static final String VALIDATOR_REPOSITORY_AT_EXPECTED_LOCATION_AND_ELSEWHERE = "validator.repository.object.at.expected.location.and.elsewhere";
    public static final String VALIDATOR_REPOSITORY_EXPIRED_REVOKED_OBJECT = "validator.repository.expired.revoked.object";
    public static final String VALIDATOR_REPOSITORY_TA_CERT_NOT_UNIQUE = "validator.repository.trust.anchor.certificate.not.unique";
    public static final String VALIDATOR_REPOSITORY_TA_CERT_URI_NOT_UNIQUE = "validator.repository.trust.anchor.certificate.uri.not.unique";
    public static final String VALIDATOR_REPOSITORY_OBJECT_IS_OLDER_THAN_PREVIOUS_OBJECT = "repository.object.is.older.than.previous.object";

    // Problems fetching
    public static final String VALIDATOR_REPO_EXECUTION = "validator.repo.execution";
}
