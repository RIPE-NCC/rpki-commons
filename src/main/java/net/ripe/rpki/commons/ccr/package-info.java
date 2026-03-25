/**
 * Provides an implementation of the Canonical Cache Representation (CCR) content type in the RPKI.
 *
 * <p>
 * CCR is a DER-encoded data interchange format which can be used to represent various aspects of the state of a
 * validated cache at a particular point in time. The CCR profile is a compact and versatile format well-suited for
 * a diverse set of applications suchas audit trail keeping, validated payload dissemination, and analytics pipelines.
 * </p>
 *
 * <p>
 * The full CCR state is represented by {@link net.ripe.rpki.commons.ccr.RPKICanonicalCacheRepresentation}. Each of the
 * other records in this package a specific part of the state. All records can encode themselves into the respective
 * ASN.1 notation, and can decode themselves from it.
 * </p>
 *
 * <p>
 * By design, the default constructors of records don't transform or validate. This allows to produce CCR state that is
 * not completely valid according to specifications. Where relevant, additional factory methods (<code>from</code>) are
 * provided to more conveniently produce correct state from plain java objects.
 * </p>
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-sidrops-rpki-ccr-02.txt">draft-ietf-sidrops-rpki-ccr-02</a>
 */
package net.ripe.rpki.commons.ccr;
