RPKI - Commons
==============

License
-------

Copyright (c) 2010-2023 RIPE NCC
All rights reserved.

This software, including all its separate source codes, is licensed under the
terms of the BSD 3-Clause License. If a copy of the license was not distributed
to you, you can obtain one at
https://github.com/RIPE-NCC/rpki-commons/blob/main/LICENSE.txt.

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

Releasing
----------

To release a version of rpki-commons you can push a tag
`rpki-commons-<VERSION>`. The Github release action will build and
publish the artifacts for `<VERSION>`. E.g. a tag `rpki-commons-1.0`
updates the POM version to `1.0` and then builds and releases the
artifacts.

After successful deployment update the pom version to point to the
next (snapshot) release, e.g. `1.1-SNAPSHOT` after releasing `1.0`.

## Changelog

## 2023-xx-xx 1.35
  * Build targets JDK 11
  * Prefixes in ROAs are sorted by (prefix, maxlength - missing first)

### 2023-06-26 1.34
  * Add `GenericRpkiSignedObjectParser` to parse object type from `content-type` and signing time.
  * Update a number of dependencies.
  * Verify non-overlap, not being continous, being in order of resource
    extension elements.

### 2023-04-20 1.33
  * Add `ResourceExtension` class to represent the RFC3779 resource extension.

### 2022-11-16 1.32
  * Use ImmutableResourceSet to store resources of X509ResourceCertificate.
    This breaks serialisation compatibility.

### 2022-11-09 1.31
  * Validate that ASPA customer ASN does not appear in provider ASNs.

### 2022-05-11 1.30
  * Improve binary signing time support for CMS
  * Support ASPA CMS objects based on draft standard and sidrops mailing list
    ASN.1 schema.
  * Add JDK 17 to build matrix in Github actions
  * Add ASPA support

### 2022-03-01 1.29
  * Support RFC8183 `publisher_request` and `repository_response` XML messages.
  * Validate that provisioning identity certificates are self-signed.

### 2022-02-01 version 1.28
  * xstream 1.4.18

### 2022-01-26 version 1.27
  * Daxon-HE, joda-time, guava dependencies updated to newer versions.
  * Depend on ipresource-1.49 fixing parsing some "IPv4 mapped to IPv6" addresses.

### 2022-01-20 version 1.26

  * LICENSE is now in README and repository and not explicitly part of each file.
  * Copyright year updated to 2022
  * Check KeyUsage bits in resource certificates
  * Added multiple BBN compliance test certificates as unit-tests
  * Simplified Base64 encoding
  * Use and support bouncy castle 1.70
  * ipresource 1.48 (removes test dependencies from non-test scopes)

### 2021-08-31 version 1.24,1.25

Add factory for non-namespace aware XML builder to prevent code duplication.

### 2021-08 version 1.23

XStream 1.4.18

### 2020-2021 version 1.17-1.22

 Refactored the XML parsing to use manually constructed parsers for untrusted
 documents. Only internal documents use XStream.

### 2020-10 version 1.16

Upgrade XStream for security updates.

Various other dependency upgrades.


### 2020-11 version 1.15

Validate that manifest `this update time` is before `next update time`.

Manifest entry file names should only refer to current directory and
use a limited set of allowed characters.

Validate that SIA and CRL URIs have the hostname specified and are not
opaque.

Upgrade to bouncy castle 1.67.

### 2020-10 version 1.14

Validate subject information access (SIA) entries according to RFC6487
section 4.8.8.

Validate issuer and subject distinguished names according to RFC6487
sections 4.4 and 4.5.

Use case insensitive comparions of URI scheme component.

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
