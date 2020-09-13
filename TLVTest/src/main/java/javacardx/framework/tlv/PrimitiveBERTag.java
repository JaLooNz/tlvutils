package javacardx.framework.tlv;

import javacardx.framework.Util;

/**
 * The PrimitiveBERTag class encapsulates a primitive BER TLV tag. The rules on
 * the allowed encoding of the Tag field is based on the ASN.1 BER encoding
 * rules of ISO/IEC 8825-1:2002.
 * <p/>
 * The {@link BERTag} class and the subclasses {@link ConstructedBERTag} and
 * {@link PrimitiveBERTag}, also provide static methods to parse or edit a BER
 * Tag structure representation in a byte array.
 */
public class PrimitiveBERTag extends BERTag {
	/**
	 * Constructor creates an empty {@link PrimitiveBERTag} object capable of
	 * encapsulating a primitive BER TLV Tag. All implementations must support at
	 * least 3 byte Tags which can encode tag numbers up to 0x3FFF.
	 */
	public PrimitiveBERTag() {

	}

	@Override
	public void init(byte[] bArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {
		if (verifyFormat(bArray, bOff)) {
			if (isConstructed(bArray, bOff))
				TLVException.throwIt(TLVException.MALFORMED_TAG);

			short tagLen = size(bArray, bOff);
			tagBytes = new byte[tagLen];
			Util.arrayCopyNonAtomic(bArray, (short) bOff, tagBytes, (short) 0, (short) tagLen);
		} else {
			TLVException.throwIt(TLVException.MALFORMED_TAG);
		}
	}
}
