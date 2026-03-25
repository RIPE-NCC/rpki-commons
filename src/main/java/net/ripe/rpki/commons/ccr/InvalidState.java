package net.ripe.rpki.commons.ccr;

/**
 * Exception to indicate that some aspect of the CCR encoded state is invalid.
 */
public class InvalidState extends Exception {
    public InvalidState(String message) {
        super(message);
    }
}
