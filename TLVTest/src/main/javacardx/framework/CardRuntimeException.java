package javacardx.framework;

public class CardRuntimeException extends Throwable {


    public short reason;

    /**
     * Constructs a CardRuntimeException instance with the specified reason. To conserve on
     * resources, use the throwIt() method to employ the Java Card runtime environment-owned
     * instance of this class.
     *
     * @param reason the reason for the exception
     */
    public CardRuntimeException(short reason) {
        setReason(reason);
    }

    /**
     * Throws the Java Card runtime environment-owned instance of CardRuntimeException with the
     * specified reason.
     * <p>
     * Java Card runtime environment-owned instances of exception classes are temporary Java Card
     * runtime environment Entry Point Objects and can be accessed from any applet context.
     * References to these temporary objects cannot be stored in class variables or instance
     * variables or array components. See Runtime Environment Specification for the Java Card
     * Platform, section 6.2.1 for details.
     *
     * @param reason the reason for the exception
     * @throws TLVException always
     */
    public static void throwIt(short reason) throws CardRuntimeException {
        throw new CardRuntimeException(reason);
    }

    /**
     * Gets the reason code
     *
     * @return the reason for the exception
     */
    public short getReason() {
        return this.reason;
    }

    /**
     * Sets the reason code. Even if a transaction is in progress, the update of the internal reason
     * field shall not participate in the transaction.
     *
     * @param reason the reason for the exception
     */
    public void setReason(short reason) {
        this.reason = reason;
    }
}
