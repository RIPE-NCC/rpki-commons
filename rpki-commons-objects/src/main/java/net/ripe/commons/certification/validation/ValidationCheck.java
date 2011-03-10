package net.ripe.commons.certification.validation;

import net.ripe.utils.support.ValueObjectSupport;

public class ValidationCheck extends ValueObjectSupport {

	private static final long serialVersionUID = 1L;

	private boolean status;

	private String key;

	private Object[] params;


	public ValidationCheck(boolean status, String key, Object... params) {
		this.status = status;
		this.key = key;
		this.params = params;
	}

	public String getKey() {
		return key;
	}

	public boolean isOk() {
		return status;
	}

	public Object[] getParams() {
		return params;
	}

}