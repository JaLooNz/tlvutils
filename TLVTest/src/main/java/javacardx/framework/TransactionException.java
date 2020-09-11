package javacardx.framework;

/**
 * TransactionException represents an exception in the transaction subsystem. The methods referred
 * to in this class are in the JCSystem class.
 * <p>
 * The JCSystem class and the transaction facility throw Java Card runtime environment-owned
 * instances of TransactionException.
 * <p>
 * Java Card runtime environment-owned instances of exception classes are temporary Java Card
 * runtime environment Entry Point Objects and can be accessed from any applet context. References
 * to these temporary objects cannot be stored in class variables or instance variables or array
 * components. See Runtime Environment Specification, Java Card Platform, Classic Edition,
 * section 6.2.1 for details.
 */
public class TransactionException extends CardRuntimeException {

	private static final long serialVersionUID = 4388355742906924848L;
	public static final short BUFFER_FULL = 3;
    public static final short IN_PROGRESS = 1;
    public static final short INTERNAL_FAILURE = 4;
    public static final short NOT_IN_PROGRESS = 2;

    /**
     * Constructs a TransactionException  instance with the specified reason. To conserve on
     * resources, use the throwIt() method to employ the Java Card runtime environment-owned
     * instance of this class.
     *
     * @param reason the reason for the exception
     */
    public TransactionException(short reason) {
        super(reason);
    }

    /**
     * Throws the Java Card runtime environment-owned instance of TransactionException  with the
     * specified reason.
     * <p>
     * Java Card runtime environment-owned instances of exception classes are temporary Java Card
     * runtime environment Entry Point Objects and can be accessed from any applet context.
     * References to these temporary objects cannot be stored in class variables or instance
     * variables or array components. See Runtime Environment Specification for the Java Card
     * Platform, section 6.2.1 for details.
     *
     * @param reason the reason for the exception
     * @throws TransactionException always
     */
    public static void throwIt(short reason) throws TransactionException {
        throw new TransactionException(reason);
    }
}
