package net.ripe.rpki.commons.provisioning.protocol;

public enum ResponseExceptionType {
    BAD_DATA(400 /*HttpServletResponse.SC_BAD_REQUEST*/, "Could not validate client's request"),
    UNKNOWN_PROVISIONING_URL(400, "Provisioning URL not recognized"),
    UNKNOWN_SENDER(400, "sender not recognized"),
    UNKNOWN_RECIPIENT(400, "recipient not recognized"),
    BAD_SENDER_AND_RECIPIENT(400, "sender and recipient do not match"),
    POTENTIAL_REPLAY_ATTACK(400, "potential replay attack (request signed before last seen signing time)"),

    THROTTLING(503 /*HttpServletResponse.SC_SERVICE_UNAVAILABLE*/, "The server cannot handle your request at this time");

    private final int httpResponseCode;
    private final String description;

    ResponseExceptionType(int httpResponseCode, String description) {
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
