RPKI - Commons
==============

License
-------

This library is distributed under the BSD License.
See: https://raw.github.com/RIPE-NCC/rpki-commons/master/LICENSE.txt

Description
-----------

Resource Certification is a robust security framework for verifying the
association between resource holders and their Internet resources. In this
context, 'resource holders' are organizations such as Regional Internet
Registries (RIRs), Local Internet Registries (LIRs), Internet Service Providers
(ISPs), or end-user organizations, while 'Internet resources' are IPv4 and IPv6
address blocks and Autonomous System (AS) numbers.

This library contains an implementation of an X.509 v3 certificate extension
which binds a list of IP address blocks or prefixes to the subject of
a certificate (IP Address Delegation Extension).

This library also contains an implementation of other RPKI signed objects:

- ROA CMS: The purpose of a ROA is to express authorization for an AS to
  originate a route to the prefix(es) in the ROA.

- Manifest CMS: A manifest is a signed object (file) that contains a listing of
  all the signed objects (files) in the repository publication point (directory)
associated with an authority responsible for publishing in the repository.

- CRL: A signed, timestamped list identifying a set of certificates that are no
  longer considered valid by the certificate issuer.

- Ghostbusters Record (RFC 6493): A signed vCard (RFC 6350) that includes
  contact information of an RPKI CA certificate maintainer.

This library supports the concept of path validation, the process that verifies
the binding between the subject and the subject-public-key defined in the target
certificate, using a trust anchor and set of known constraints.

This library also contains an implementation of the RPKI certificate
provisioning protocol.


## Changelog

### 2020-07 version 1.13

Fix inconsistencies in ValidationOptions behaviour.

### 2020-07 version 1.12.0

Provide option to avoid storing passed checks in validation result to
reduce memory usage.

### 2020-07 version 1.11.0

This release improves performance of the validation process.

WARNING: The internal implementation of some classes have changed,
breaking Java serialization compatibility with previous versions of
this library.

### 2020-06 version 1.10

This release provide configurable options for handling of not-yet valid or expired objects.

When you want to accept expired/stale objects, you can set an grace period through
`ValidationOptions.withStaleConfiguration(maxCrlStalePeriod, maxMftStalePeriod)`

If you are happy with warnings (behaviour of 1.9.0) you can use presets:
`ValidationOptions.defaultRipeNccValidator()`

There is also presets that will reject CRL/MFT having less than 7 hours of validity.
`ValidationOptions.strictValidations()`

Grace perioud behaviour are as follows:
 - Warn for CRLs with nextUpdate in grace period, reject CRLs with
   nextUpdate outside grace period.
 - Warn for manifests with nextUpdate in grace period, reject manifests
   with nextUpdate outside grace period.

Fixes:
 - Reject CRLs with thisUpdate in future.
 - Reject manifests with thisUpdate in future.


### 2020-04-24 version 1.9.0

 - Revert Bouncy Castle version.

### 2020-03-31 version 1.8.0

 - Update to recent Guava, Bouncy Castle, Joda Time version.

### 2019-11-27 version 1.7.3

 - Fix: make sure all the time operations are doen using UTC.

### 2019-11-27 version 1.7

 - Update to recent XStream version.

 - Use class whitelisting for XStream deserialization.

### 2019-11-25 version 1.6

- GitLab continuous integration.

### 2017-11-28 version 1.3

- Java 1.8 or higher required

- Support parsing and validation of Ghostbusters records (RFC 6493).

- Improve error messages and reporting.

- Handle the new XML format for out-of-band identity exchange as described in
  https://tools.ietf.org/html/draft-ietf-sidr-rpki-oob-setup-04.

## Continuous Integration

When a pull request is merged to master GitLab CI builds a snapshot release
and publishes it on maven central.

Running `mvn release:prepare` locally creates a release version and
tags it. This version automatically is published by GitLab CI. The new
snapshot version will also be set and committed.
