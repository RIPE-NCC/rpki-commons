package net.ripe.rpki.commons.validation;

import org.apache.commons.lang3.Validate;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

import java.io.Serializable;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.Map.Entry;

public final class ValidationResult {

    private static final String[] EMPTY_PARAM = {};

    private Clock clock = Clock.systemUTC();

    private final Map<ValidationLocation, ResultsPerLocation> results = new TreeMap<>();

    private ValidationLocation currentLocation;

    private final Map<ValidationLocation, List<ValidationMetric>> metrics = new TreeMap<>();

    private boolean storingPassingChecks = true;

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

    public ValidationResult withClock(Clock clock) {
        this.clock = clock;
        return this;
    }

    public Instant now() {
        return clock.instant();
    }

    public ValidationResult withoutStoringPassingChecks() {
        if (this.storingPassingChecks) {
            this.storingPassingChecks = false;
            for (ResultsPerLocation entry : this.results.values()) {
                entry.passed.clear();
            }
        }
        return this;
    }

    public boolean isStoringPassingChecks() {
        return storingPassingChecks;
    }

    public ValidationResult setLocation(ValidationLocation location) {
        currentLocation = location;
        return this;
    }

    private ResultsPerLocation getCurrentResults() {
        return results.computeIfAbsent(currentLocation, (x) -> new ResultsPerLocation());
    }

    public ValidationResult pass(String key) {
        return pass(key, EMPTY_PARAM);
    }

    public ValidationResult pass(String key, String... param) {
        if (storingPassingChecks) {
            getCurrentResults().passed.add(new ValidationCheck(ValidationStatus.PASSED, key, param));
        }
        return this;
    }

    public ValidationResult warn(String key) {
        return warn(key, EMPTY_PARAM);
    }

    public ValidationResult warn(String key, String... param) {
        getCurrentResults().warning.add(new ValidationCheck(ValidationStatus.WARNING, key, param));
        return this;
    }

    public ValidationResult error(String key) {
        return error(key, EMPTY_PARAM);
    }

    public ValidationResult error(String key, String... param) {
        getCurrentResults().error.add(new ValidationCheck(ValidationStatus.ERROR, key, param));
        return this;
    }

    public boolean warnIfFalse(boolean condition, String key) {
        return warnIfFalse(condition, key, EMPTY_PARAM);
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

    public boolean warnIfTrue(boolean condition, String key) {
        return warnIfTrue(condition, key, EMPTY_PARAM);
    }

    public boolean warnIfTrue(boolean condition, String key, String... param) {
        return warnIfFalse(!condition, key, param);
    }

    public boolean warnIfNull(Object object, String key) {
        return warnIfNull(object, key, EMPTY_PARAM);
    }

    public boolean warnIfNull(Object object, String key, String... param) {
        return warnIfTrue(object == null, key, param);
    }

    public boolean warnIfNotNull(Object object, String key) {
        return warnIfNotNull(object, key, EMPTY_PARAM);
    }

    public boolean warnIfNotNull(Object object, String key, String... param) {
        return warnIfTrue(object != null, key, param);
    }

    public ValidationResult rejectForLocation(ValidationLocation location, String key) {
        return rejectForLocation(location, key, EMPTY_PARAM);
    }

    public ValidationResult rejectForLocation(ValidationLocation location, String key, String... param) {
        ResultsPerLocation resultsPerLocation = results.computeIfAbsent(location, (x) -> new ResultsPerLocation());
        resultsPerLocation.error.add(new ValidationCheck(ValidationStatus.ERROR, key, param));
        return this;
    }

    public ValidationResult warnForLocation(ValidationLocation location, String key) {
        return warnForLocation(location, key, EMPTY_PARAM);
    }

    public ValidationResult warnForLocation(ValidationLocation location, String key, String... param) {
        ResultsPerLocation resultsPerLocation = results.computeIfAbsent(location, (x) -> new ResultsPerLocation());
        resultsPerLocation.warning.add(new ValidationCheck(ValidationStatus.WARNING, key, param));
        return this;
    }

    public boolean rejectIfFalse(boolean condition, String key) {
        return rejectIfFalse(condition, key, EMPTY_PARAM);
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

    public boolean rejectIfTrue(boolean condition, String key) {
        return rejectIfTrue(condition, key, EMPTY_PARAM);
    }

    public boolean rejectIfTrue(boolean condition, String key, String... param) {
        return rejectIfFalse(!condition, key, param);
    }

    public boolean rejectIfNull(Object object, String key) {
        return rejectIfNull(object, key, EMPTY_PARAM);
    }

    public boolean rejectIfNull(Object object, String key, String... param) {
        return rejectIfTrue(object == null, key, param);
    }

    public boolean rejectIfNotNull(Object object, String key) {
        return rejectIfNotNull(object, key, EMPTY_PARAM);
    }

    public boolean rejectIfNotNull(Object object, String key, String... param) {
        return rejectIfTrue(object != null, key, param);
    }

    public ValidationResult addMetric(String name, String value) {
        if (!metrics.containsKey(currentLocation)) {
            metrics.put(currentLocation, new ArrayList<>());
        }
        metrics.get(currentLocation).add(new ValidationMetric(name, value, clock.millis()));
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
        for (ResultsPerLocation checks: this.results.values()) {
            if (!checks.error.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasWarnings() {
        for (ResultsPerLocation checks: this.results.values()) {
            if (!checks.warning.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasNoFailuresOrWarnings() {
        return !hasFailures() && !hasWarnings();
    }

    public Set<ValidationCheck> getFailuresForCurrentLocation() {
        return new HashSet<>(getFailures(currentLocation));
    }

    public List<ValidationCheck> getFailuresForAllLocations() {
        List<ValidationCheck> failures = new ArrayList<>();
        for (ResultsPerLocation checks : results.values()) {
            failures.addAll(checks.error);
        }
        return failures;
    }

    public List<ValidationCheck> getFailures(ValidationLocation location) {
        ResultsPerLocation checks = results.get(location);
        return checks == null ? Collections.emptyList() : checks.error;
    }

    public List<ValidationCheck> getWarnings(ValidationLocation location) {
        ResultsPerLocation checks = results.get(location);
        return checks == null ? Collections.emptyList() : checks.warning;
    }

    public boolean hasFailureForCurrentLocation() {
        return hasFailureForLocation(currentLocation);
    }

    public boolean hasFailureForLocation(ValidationLocation location) {
        ResultsPerLocation checks = results.get(location);
        return checks != null && !checks.error.isEmpty();
    }

    public List<ValidationCheck> getWarnings() {
        List<ValidationCheck> warnings = new ArrayList<>();
        for (ResultsPerLocation checks : results.values()) {
            warnings.addAll(checks.warning);
        }
        return warnings;
    }

    public List<ValidationCheck> getAllValidationChecksForCurrentLocation() {
        return getAllValidationChecksForLocation(currentLocation);
    }

    public List<ValidationCheck> getAllValidationChecksForLocation(ValidationLocation location) {
        ArrayList<ValidationCheck> allChecks = new ArrayList<>();
        ResultsPerLocation resultsPerLocation = results.get(location);
        if (resultsPerLocation != null) {
            allChecks.addAll(resultsPerLocation.error);
            allChecks.addAll(resultsPerLocation.warning);
            allChecks.addAll(resultsPerLocation.passed);
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
        for (Entry<ValidationLocation, ResultsPerLocation> resultsByLocation : that.results.entrySet()) {
            ResultsPerLocation thatResults = resultsByLocation.getValue();
            if (thatResults.error.isEmpty() && thatResults.warning.isEmpty() && (thatResults.passed.isEmpty() || !this.storingPassingChecks)) {
                continue;
            }

            ResultsPerLocation thisResults = results.computeIfAbsent(resultsByLocation.getKey(), (x) -> new ResultsPerLocation());
            thisResults.error.addAll(thatResults.error);
            thisResults.warning.addAll(thatResults.warning);
            if (this.storingPassingChecks) {
                thisResults.passed.addAll(thatResults.passed);
            }
        }
        return this;
    }

    private static final class ResultsPerLocation implements Serializable {
        private static final long serialVersionUID = 1L;

        final List<ValidationCheck> error = new ArrayList<>();

        final List<ValidationCheck> warning = new ArrayList<>();

        // Average of 12-13 passed checks per location (min = 1, max = 18) as of 2020-07-08 on RIPE NCC trust anchor,
        // we use a slightly higher initial capacity to avoid re-sizing.
        final List<ValidationCheck> passed = new ArrayList<>(20);

        @Override
        public String toString() {
            return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
                    .append("error", error)
                    .append("warning", warning)
                    .append("passed", passed)
                    .toString();
        }
    }
}
