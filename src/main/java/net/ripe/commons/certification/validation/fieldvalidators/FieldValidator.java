package net.ripe.commons.certification.validation.fieldvalidators;

import java.io.Serializable;


public interface FieldValidator extends Serializable {

    ValidationResult validate(String target);
}
