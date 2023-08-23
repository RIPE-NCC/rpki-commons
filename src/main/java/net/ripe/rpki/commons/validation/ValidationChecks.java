package net.ripe.rpki.commons.validation;

import net.ripe.rpki.commons.util.RepositoryObjectType;

import static net.ripe.rpki.commons.util.RepositoryObjectType.*;
import static net.ripe.rpki.commons.validation.ValidationString.*;

public final class ValidationChecks {

    private ValidationChecks() {
    }

    public static void knownObjectType(RepositoryObjectType objectType, ValidationResult validationResult) {
        if (objectType == Unknown) {
            validationResult.error(KNOWN_OBJECT_TYPE, validationResult.getCurrentLocation().name());
        } else {
            validationResult.pass(KNOWN_OBJECT_TYPE, validationResult.getCurrentLocation().name());
        }
    }
}
