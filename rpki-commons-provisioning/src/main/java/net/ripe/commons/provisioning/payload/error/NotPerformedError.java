package net.ripe.commons.provisioning.payload.error;

import java.util.HashMap;
import java.util.Map;

public enum NotPerformedError {
    
    ALREADY_PROCESSING_REQUEST(1101),
    VERSION_NUMBER_ERROR(1102),
    UNRECOGNIZED_REQUEST_TYPE(1103),
    REQUEST_SCHEDULED_FOR_PROCESSING(1104),
    REQ_NO_SUCH_RESOURCE_CLASS(1201),
    REQ_NO_RESOURCES_ALLOTED_IN_RESOURCE_CLASS(1202),
    REQ_BADLY_FORMED_CERTIFICATE_REQUEST(1203),
    REQ_ALREADY_USED_KEY_IN_REQUEST(1204),
    REV_NO_SUCH_RESOURCE_CLASS(1301),
    REV_NO_SUCH_KEY(1302),
    INTERNAL_SERVER_ERROR(2001);

    private Integer errorCode;

    private static final Map<Integer, NotPerformedError> CODE_MAP;

    static {
        CODE_MAP = new HashMap<Integer, NotPerformedError>();

        for (NotPerformedError error : NotPerformedError.values()) {
            CODE_MAP.put(error.getErrorCode(), error);
        }
    }

    NotPerformedError(Integer errorCode) {
        this.errorCode = errorCode;
    }

    public Integer getErrorCode() {
        return errorCode;
    }

    public static NotPerformedError getError(Integer errorCode) {
        return CODE_MAP.get(errorCode);
    }
}
