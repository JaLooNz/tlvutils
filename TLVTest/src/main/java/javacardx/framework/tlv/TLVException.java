package javacardx.framework.tlv;

import com.jaloonz.tlv.utils.JCEnvironmentExceptions;

import javacardx.framework.CardRuntimeException;

/**
 * TLVException represents a TLV-related exception.
 * <p/>
 * The API classes throw Java Card runtime environment-owned instances of
 * TLVException.
 * <p/>
 * Java Card runtime environment-owned instances of exception classes are
 * temporary Java Card runtime environment Entry Point Objects and can be
 * accessed from any applet context. References to these temporary objects
 * cannot be stored in class variables, instance variables, or array components.
 */
public class TLVException extends CardRuntimeException {
	private static final long serialVersionUID = -778574823780925536L;
	public static final short EMPTY_TAG = 3;
	public static final short EMPTY_TLV = 4;
	public static final short ILLEGAL_SIZE = 2;
	public static final short INSUFFICIENT_STORAGE = 7;
	public static final short INVALID_PARAM = 1;
	public static final short MALFORMED_TAG = 5;
	public static final short MALFORMED_TLV = 6;
	public static final short TAG_NUMBER_GREATER_THAN_32767 = 9;
	public static final short TAG_SIZE_GREATER_THAN_127 = 8;
	public static final short TLV_LENGTH_GREATER_THAN_32767 = 11;
	public static final short TLV_SIZE_GREATER_THAN_32767 = 10;

	/**
	 * Constructs a TLVException with the specified reason.
	 *
	 * @param reason the reason for the exception
	 */
	public TLVException(short reason) {
		super(reason);
	}

	/**
	 * Throws the Java Card runtime environment-owned instance of TLVException with
	 * the specified reason.
	 * <p/>
	 * Java Card runtime environment-owned instances of exception classes are
	 * temporary Java Card runtime environment Entry Point Objects and can be
	 * accessed from any applet context. References to these temporary objects
	 * cannot be stored in class variables or instance variables or array
	 * components.
	 * <p/>
	 * See Runtime Environment Specification for the Java Card Platform, section
	 * 6.2.1 for details.
	 *
	 * @param reason the reason for the exception
	 * @throws TLVException always
	 */
	public static void throwIt(short reason) throws TLVException {
		JCEnvironmentExceptions.throwTLVException(reason);
	}
}
