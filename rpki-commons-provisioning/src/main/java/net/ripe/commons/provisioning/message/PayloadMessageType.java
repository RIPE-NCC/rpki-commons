package net.ripe.commons.provisioning.message;

public enum PayloadMessageType {
    // in lowercase to comply with http://tools.ietf.org/html/draft-ietf-sidr-rescerts-provisioning-09#section-3.3.1
    list,
    list_response,
    issue,
    issue_response,
    revoke,
    error_response
}
