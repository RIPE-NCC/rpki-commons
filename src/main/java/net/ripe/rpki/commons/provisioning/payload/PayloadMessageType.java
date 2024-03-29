package net.ripe.rpki.commons.provisioning.payload;

public enum PayloadMessageType {
    // in lowercase to comply with http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    list,
    list_response,
    issue,
    issue_response,
    revoke,
    revoke_response,
    error_response;

    public static boolean containsAsEnum(String name) {
        PayloadMessageType[] values = PayloadMessageType.values();

        for (PayloadMessageType value : values) {
            if (value.name().equalsIgnoreCase(name)) {
                return true;
            }
        }

        return false;
    }
}
