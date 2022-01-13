/**
 * The BSD License
 *
 * Copyright (c) 2010-2021 RIPE NCC
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
package net.ripe.rpki.commons.crypto;

import net.ripe.rpki.commons.util.EqualsSupport;
import org.apache.commons.lang3.Validate;
import java.time.Instant;

import java.io.Serializable;
import java.util.Date;

/**
 * Validity period used by the certification system. Since certificates only
 * have up-to second accuracy with validity fields, this class truncates not
 * before and not after to second accuracy.
 */
public class ValidityPeriod extends EqualsSupport implements Serializable {
    private static final long serialVersionUID = 2L;

    private final Instant notValidBefore;
    private final Instant notValidAfter;

    public ValidityPeriod() {
        this((Date) null, (Date) null);
    }

    public ValidityPeriod(Instant notValidBefore, Instant notValidAfter) {
        this.notValidBefore = notValidBefore == null ? null : truncatedMillis(notValidBefore.toEpochMilli());
        this.notValidAfter = notValidAfter == null ? null : truncatedMillis(notValidAfter.toEpochMilli());
        Validate.isTrue(isDateOrderingValid(this.notValidBefore, this.notValidAfter), "Got an invalid validatity time from: " + notValidBefore + " to: " + notValidAfter);
    }

    public ValidityPeriod(Date notValidBefore, Date notValidAfter) {
        this.notValidBefore = (notValidBefore == null) ? null : truncatedMillis(notValidBefore.getTime());
        this.notValidAfter = (notValidAfter == null) ? null : truncatedMillis(notValidAfter.getTime());
        Validate.isTrue(isDateOrderingValid(this.notValidBefore, this.notValidAfter), "Got an invalid validatity time from: " + notValidBefore + " to: " + notValidAfter);
    }

    private static boolean isDateOrderingValid(Instant notValidBefore, Instant notValidAfter) {
        return (notValidBefore == null || notValidAfter == null || notValidBefore.equals(notValidAfter) || notValidBefore.isBefore(notValidAfter));
    }

    // Match resolution of certificate validity period (seconds)
    private Instant truncatedMillis(long millisSinceEpoch) {
        return Instant.ofEpochSecond(millisSinceEpoch / 1000);
    }

    public Instant getNotValidAfter() {
        return notValidAfter;
    }

    public Instant getNotValidBefore() {
        return notValidBefore;
    }

    public ValidityPeriod withNotValidBefore(Instant notValidBefore) {
        return new ValidityPeriod(notValidBefore, getNotValidAfter());
    }

    public ValidityPeriod withNotValidAfter(Instant notValidAfter) {
        return new ValidityPeriod(getNotValidBefore(), notValidAfter);
    }

    public boolean contains(ValidityPeriod other) {
        return isValidAt(other.getNotValidBefore()) && isValidAt(other.getNotValidAfter());
    }

    @Deprecated
    public boolean isExpiredNow() {
        return isExpiredAt(Instant.now());
    }

    public boolean isExpiredAt(Instant instant) {
        return notValidAfter != null && instant.isAfter(getNotValidAfter());
    }

    @Deprecated
    public boolean isValidNow() {
        return isValidAt(Instant.now());
    }

    public boolean isValidAt(Instant instant) {
        if (instant == null) {
            return !isClosed();
        } else {
            return (notValidBefore == null || !instant.isBefore(getNotValidBefore()))
                    && (notValidAfter == null || !instant.isAfter(getNotValidAfter()));
        }
    }

    /**
     * @return true if this instances notValidBefore and notValidAfter are both
     *         specified.
     */
    public boolean isClosed() {
        return notValidBefore != null && notValidAfter != null;
    }

    /**
     * Calculates the intersection of two validity periods, taking into account
     * open-ended validity periods.
     *
     * @param other the validity period to intersect with.
     * @return the intersection of this and the other validity period, or null
     *         if there is no overlap.
     */
    public ValidityPeriod intersectedWith(ValidityPeriod other) {
        Instant latestNotValidBefore = latestDateTimeOf(notValidBefore, other.notValidBefore);
        Instant earliestNotValidAfter = earliestDateTimeOf(notValidAfter, other.notValidAfter);
        if (isDateOrderingValid(latestNotValidBefore, earliestNotValidAfter)) {
            return new ValidityPeriod(latestNotValidBefore, earliestNotValidAfter);
        } else {
            // we got disjoint time intervals
            return null;
        }
    }

    private Instant earliestDateTimeOf(Instant date1, Instant date2) {
        if (date1 == null) {
            return date2;
        }
        if (date2 == null) {
            return date1;
        }
        return date1.isBefore(date2) ? date1 : date2;
    }

    private Instant latestDateTimeOf(Instant date1, Instant date2) {
        if (date1 == null) {
            return date2;
        }
        if (date2 == null) {
            return date1;
        }
        return date1.isAfter(date2) ? date1 : date2;
    }

    @Override
    public String toString() {
        return getNotValidBefore() + " - " + getNotValidAfter();
    }
}
