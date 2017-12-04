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

### 2017-11-28 version 1.3

- Java 1.8 or higher required

- Support parsing and validation of Ghostbusters records (RFC 6493).

- Improve error messages and reporting.

- Handle the new XML format for out-of-band identity exchange as described in
  https://tools.ietf.org/html/draft-ietf-sidr-rpki-oob-setup-04.
