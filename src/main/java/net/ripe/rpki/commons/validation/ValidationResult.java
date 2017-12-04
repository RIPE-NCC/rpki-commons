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

import org.apache.commons.lang.Validate;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;
import org.joda.time.DateTimeUtils;

import java.io.Serializable;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

public final class ValidationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private Map<ValidationLocation, Map<ValidationStatus, List<ValidationCheck>>> results = new LinkedHashMap<ValidationLocation, Map<ValidationStatus, List<ValidationCheck>>>();

    private ValidationLocation currentLocation;

    private Map<ValidationLocation, List<ValidationMetric>> metrics = new LinkedHashMap<ValidationLocation, List<ValidationMetric>>();

    private ValidationResult(ValidationLocation location) {
        setLocation(location);
    }

    public static ValidationResult withLocation(URI uri) {
        return new ValidationResult(new ValidationLocation(uri));
    }

    public static ValidationResult withLocation(String name) {
        return new ValidationResult(new ValidationLocation(name));
    }

    public static ValidationResult withLocation(ValidationLocation location) {
        return new ValidationResult(location);
    }

    public ValidationResult setLocation(ValidationLocation location) {
        currentLocation = location;

        if (!results.containsKey(currentLocation)) {
            Map<ValidationStatus, List<ValidationCheck>> locationResults = new LinkedHashMap<ValidationStatus, List<ValidationCheck>>();
            locationResults.put(ValidationStatus.ERROR, new ArrayList<ValidationCheck>());
            locationResults.put(ValidationStatus.WARNING, new ArrayList<ValidationCheck>());
            locationResults.put(ValidationStatus.PASSED, new ArrayList<ValidationCheck>());
            results.put(currentLocation, locationResults);
        }
        return this;
    }

    private ValidationResult setValidationCheckForCurrentLocation(ValidationStatus status, String key, String... param) {
        Map<ValidationStatus, List<ValidationCheck>> currentResults = results.get(currentLocation);
        List<ValidationCheck> checksForStatus = currentResults.get(status);
        checksForStatus.add(new ValidationCheck(status, key, param));
        return this;
    }

    public ValidationResult pass(String key, String... param) {
        setValidationCheckForCurrentLocation(ValidationStatus.PASSED, key, param);
        return this;
    }

    public ValidationResult warn(String key, String... param) {
        setValidationCheckForCurrentLocation(ValidationStatus.WARNING, key, param);
        return this;
    }

    public ValidationResult error(String key, String... param) {
        setValidationCheckForCurrentLocation(ValidationStatus.ERROR, key, param);
        return this;
    }

    public boolean warnIfFalse(boolean condition, String key, String... param) {
        Validate.notNull(key, "key is required");
        if (condition) {
            pass(key, param);
        } else {
            warn(key, param);
        }
        return condition;
    }

    public boolean warnIfTrue(boolean condition, String key, String... param) {
        return warnIfFalse(!condition, key, param);
    }

    public boolean warnIfNull(Object object, String key, String... param) {
        return warnIfTrue(object == null, key, param);
    }

    public boolean warnIfNotNull(Object object, String key, String... param) {
        return warnIfTrue(object != null, key, param);
    }

    public ValidationResult rejectForLocation(ValidationLocation location, String key, String... param) {
        ValidationLocation locationBefore = currentLocation;
        setLocation(location);
        setValidationCheckForCurrentLocation(ValidationStatus.ERROR, key, param);
        setLocation(locationBefore);
        return this;
    }

    public ValidationResult warnForLocation(ValidationLocation location, String key, String... param) {
        ValidationLocation locationBefore = currentLocation;
        setLocation(location);
        setValidationCheckForCurrentLocation(ValidationStatus.WARNING, key, param);
        setLocation(locationBefore);
        return this;
    }

    public boolean rejectIfFalse(boolean condition, String key, String... param) {
        Validate.notNull(key, "key is required");
        if (condition) {
            pass(key, param);
        } else {
            error(key, param);
        }
        return condition;
    }

    public boolean rejectIfTrue(boolean condition, String key, String... param) {
        return rejectIfFalse(!condition, key, param);
    }

    public boolean rejectIfNull(Object object, String key, String... param) {
        return rejectIfTrue(object == null, key, param);
    }

    public boolean rejectIfNotNull(Object object, String key, String... param) {
        return rejectIfTrue(object != null, key, param);
    }

    public ValidationResult addMetric(String name, String value) {
        if (!metrics.containsKey(currentLocation)) {
            metrics.put(currentLocation, new ArrayList<ValidationMetric>());
        }
        metrics.get(currentLocation).add(new ValidationMetric(name, value, DateTimeUtils.currentTimeMillis()));
        return this;
    }

    // Accessors

    public Set<ValidationLocation> getValidatedLocations() {
        return results.keySet();
    }

    public ValidationLocation getCurrentLocation() {
        return currentLocation;
    }

    public boolean hasFailures() {
        for (Map<ValidationStatus, List<ValidationCheck>> checks: this.results.values()) {
            List<ValidationCheck> errors = checks.get(ValidationStatus.ERROR);
            if (errors != null && !errors.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasWarnings() {
        for (Map<ValidationStatus, List<ValidationCheck>> checks: this.results.values()) {
            List<ValidationCheck> errors = checks.get(ValidationStatus.WARNING);
            if (errors != null && !errors.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasNoFailuresOrWarnings() {
        return !hasFailures() && !hasWarnings();
    }

    public Set<ValidationCheck> getFailuresForCurrentLocation() {
        return new HashSet<ValidationCheck>(getFailures(currentLocation));
    }

    public List<ValidationCheck> getFailuresForAllLocations() {
        List<ValidationCheck> failures = new ArrayList<ValidationCheck>();
        for (ValidationLocation location : getValidatedLocations()) {
            failures.addAll(getChecks(location, ValidationStatus.ERROR));
        }
        return failures;
    }

    public List<ValidationCheck> getFailures(ValidationLocation location) {
        return getChecks(location, ValidationStatus.ERROR);
    }

    public List<ValidationCheck> getWarnings(ValidationLocation location) {
        return getChecks(location, ValidationStatus.WARNING);
    }

    public boolean hasFailureForCurrentLocation() {
        return hasFailureForLocation(currentLocation);
    }

    public boolean hasFailureForLocation(ValidationLocation location) {
        return !getFailures(location).isEmpty();
    }

    public List<ValidationCheck> getWarnings() {
        List<ValidationCheck> warnings = new ArrayList<ValidationCheck>();
        for (ValidationLocation location : getValidatedLocations()) {
            warnings.addAll(getChecks(location, ValidationStatus.WARNING));
        }
        return warnings;
    }

    private List<ValidationCheck> getChecks(ValidationLocation location, ValidationStatus status) {
        if (results.containsKey(location)) {
            return results.get(location).get(status);
        } else {
            return new ArrayList<ValidationCheck>();
        }
    }


    public List<ValidationCheck> getAllValidationChecksForCurrentLocation() {
        return getAllValidationChecksForLocation(currentLocation);
    }

    public List<ValidationCheck> getAllValidationChecksForLocation(ValidationLocation location) {
        ArrayList<ValidationCheck> allChecks = new ArrayList<ValidationCheck>();
        if (results.containsKey(location)) {
            Map<ValidationStatus, List<ValidationCheck>> locationChecksMap = results.get(location);
            allChecks.addAll(locationChecksMap.get(ValidationStatus.ERROR));
            allChecks.addAll(locationChecksMap.get(ValidationStatus.WARNING));
            allChecks.addAll(locationChecksMap.get(ValidationStatus.PASSED));
        }

        return allChecks;
    }

    public ValidationCheck getResultForCurrentLocation(String checkKey) {
        return getResult(currentLocation, checkKey);
    }

    public ValidationCheck getResult(ValidationLocation location, String checkKey) {
        final List<ValidationCheck> allChecks = getAllValidationChecksForLocation(location);
        for (ValidationCheck check : allChecks) {
            if (check.getKey().equals(checkKey)) {
                return check;
            }
        }
        return null;
    }

    public List<ValidationMetric> getMetrics(ValidationLocation location) {
        if (metrics.containsKey(location)) {
            return Collections.unmodifiableList(metrics.get(location));
        } else {
            return Collections.emptyList();
        }
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.SHORT_PREFIX_STYLE);
    }

    public ValidationResult addAll(ValidationResult that) {
        for (Entry<ValidationLocation, Map<ValidationStatus, List<ValidationCheck>>> resultsByLocation : that.results.entrySet()) {
            Map<ValidationStatus, List<ValidationCheck>> map = results.get(resultsByLocation.getKey());
            if (map == null) {
                map = new LinkedHashMap<ValidationStatus, List<ValidationCheck>>();
                this.results.put(resultsByLocation.getKey(), map);
            }
            for (Entry<ValidationStatus, List<ValidationCheck>> checks : resultsByLocation.getValue().entrySet()) {
                List<ValidationCheck> list = map.get(checks.getKey());
                if (list == null) {
                    list = new ArrayList<ValidationCheck>();
                    map.put(checks.getKey(), list);
                }
                list.addAll(checks.getValue());
            }
        }
        return this;
    }
}
