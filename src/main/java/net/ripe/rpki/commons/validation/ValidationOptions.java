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
package net.ripe.rpki.commons.validation;


import org.joda.time.Duration;

/**
 * User controlled options to use when validating objects.
 */
public class ValidationOptions {

    /**
     * Flag to switch whether we would reject stale manifest and CRL under certain max stale period.
     * Turning this on will activate the {@link ValidationOptions#crlMaxStalePeriod} and {@link ValidationOptions#manifestMaxStalePeriod} checks.
     *
     */
    private boolean strictManifestCRLValidityChecks = false;

    /**
     * When {@link ValidationOptions#strictManifestCRLValidityChecks} is enabled, this is the grace period for the
     * NEXT_UPDATE_TIME of CRL. When a crl is in the grace period, the crl causes a warning on
     * validation instead of a failure.
     */
    private Duration crlMaxStalePeriod = Duration.ZERO;

    /**
     *  When {@link ValidationOptions#strictManifestCRLValidityChecks} is enabled, this is the grace period for the
     *  NEXT_UPDATE_TIME of Manifest. When a manifest is in the grace period, the manifest causes
     *  a warning on validation instead of a failure.
     *
     * This grace period is not applied to the EE certificate.
     */
    private Duration manifestMaxStalePeriod = Duration.ZERO;

    /**
     * Setting this will allow resources over claim on X509ResourceCertificateParentChildLooseValidator.
     * Instead of rejected, it will only produce warnin on overclaim of child resources.
     */
    private boolean allowOverclaimParentChild = false;


    public Duration getCrlMaxStalePeriod() {
        return this.crlMaxStalePeriod;
    }

    public Duration getManifestMaxStalePeriod() {
        return manifestMaxStalePeriod;
    }

    public void setCrlMaxStalePeriod(Duration maxStalePeriod) {
        this.crlMaxStalePeriod = maxStalePeriod;
    }

    public void setManifestMaxStalePeriod(Duration maxStalePeriod) {
        this.manifestMaxStalePeriod = maxStalePeriod;
    }

    public boolean isAllowOverclaimParentChild() {
        return allowOverclaimParentChild;
    }

    public void setAllowOverclaimParentChild(boolean allowOverclaimParentChild) {
        this.allowOverclaimParentChild = allowOverclaimParentChild;
    }

    public boolean isStrictManifestCRLValidityChecks() {
        return strictManifestCRLValidityChecks;
    }

    public void setStrictManifestCRLValidityChecks(boolean strictManifestCRLValidityChecks) {
        this.strictManifestCRLValidityChecks = strictManifestCRLValidityChecks;
    }
}
