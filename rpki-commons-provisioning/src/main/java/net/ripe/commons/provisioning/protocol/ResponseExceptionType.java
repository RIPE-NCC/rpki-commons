package net.ripe.commons.provisioning.protocol;

public enum ResponseExceptionType {
    BAD_DATA(400 /*HttpServletResponse.SC_BAD_REQUEST*/),

    THROTTLING(503 /*HttpServletResponse.SC_SERVICE_UNAVAILABLE*/);

    private int httpResponseCode;

    private ResponseExceptionType(int httpResponseCode) {
        this.httpResponseCode = httpResponseCode;
    }

    public int getHttpResponseCode() {
        return httpResponseCode;
    }
}
