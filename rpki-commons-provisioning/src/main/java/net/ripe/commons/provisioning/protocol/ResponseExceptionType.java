package net.ripe.commons.provisioning.protocol;

public enum ResponseExceptionType {
    BAD_DATA(400 /*HttpServletResponse.SC_BAD_REQUEST*/, "Could not validate client's request"),

    THROTTLING(503 /*HttpServletResponse.SC_SERVICE_UNAVAILABLE*/, "The server cannot handle your request at this time");

    private int httpResponseCode;
    private String description;

    private ResponseExceptionType(int httpResponseCode, String description) {
        this.httpResponseCode = httpResponseCode;
        this.description = description;
    }

    public int getHttpResponseCode() {
        return httpResponseCode;
    }

    public String getDescription() {
        return description;
    }
}
