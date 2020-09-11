package javacardx.framework.tlv;

import javacardx.framework.Util;

/**
 * The abstract BERTag class encapsulates a BER TLV tag. The rules on the
 * allowed encoding of the Tag field are based on the ASN.1 BER encoding rules
 * of ISO/IEC 8825-1:2002.
 * <p/>
 * The BERTag class and the subclasses ConstructedBERTag and PrimitiveBERTag,
 * also provide static methods to parse or edit a BER Tag structure
 * representation in a byte array.
 */
public abstract class BERTag {
	public static final byte BER_TAG_CLASS_MASK_APPLICATION = 1;
	public static final byte BER_TAG_CLASS_MASK_CONTEXT_SPECIFIC = 2;
	public static final byte BER_TAG_CLASS_MASK_PRIVATE = 3;
	public static final byte BER_TAG_CLASS_MASK_UNIVERSAL = 0;
	public static final boolean BER_TAG_TYPE_CONSTRUCTED = true;
	public static final boolean BER_TAG_TYPE_PRIMITIVE = false;
	private static byte[] buffer;
	protected byte[] tagBytes;

	/**
	 * Constructor creates an empty BERTLV Tag object capable of encapsulating a BER
	 * TLV Tag.
	 */
	protected BERTag() {
		buffer = new byte[4];
	}

	/**
	 * Create a BERTLV Tag object from the binary representation in the byte array.
	 * All implementations must support tag numbers up to 0x3FFF.
	 * <p/>
	 * Note that the returned BERTag must be cast to the correct subclass:
	 * PrimitiveBERTag or ConstructedBERTag to access their specialized API.
	 *
	 * @param bArray the byte array containing the binary representation
	 * @param bOff   the offset within bArray where the tag binary begins
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if bArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        tag number requested is larger than
	 *                                        the supported maximum size</li>
	 *                                        <li>TLVException.MALFORMED_TAG if tag
	 *                                        representation in the byte array is
	 *                                        malformed</li>
	 *                                        </ul>
	 */
	public static BERTag getInstance(byte[] bArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {
		BERTag tag = null;
		
		if (isConstructed(bArray, bOff)) {
			tag = new ConstructedBERTag();
		} else {
			tag = new PrimitiveBERTag();
		}
		tag.init(bArray, bOff);
		return tag;
	}

	/**
	 * Writes the BER Tag bytes representing the specified tag class, constructed
	 * flag and the tag number as a BER Tag representation in the specified byte
	 * array
	 *
	 * @param tagClass      encodes the tag class. Valid codes are the
	 *                      BER_TAG_CLASS_MASK_* constants defined above. See
	 *                      BER_TAG_CLASS_MASK_APPLICATION.
	 * @param isConstructed true if the tag is constructed, false if primitive
	 * @param tagNumber     is the tag number.
	 * @param outArray      output byte array
	 * @param bOff          offset within byte array containing first byte
	 * @return size of BER Tag output bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        tag size is larger than the supported
	 *                                        maximum size or 32767</li>
	 *                                        <li>TLVException.INVALID_PARAM if
	 *                                        tagClass parameter is invalid or if
	 *                                        the tagNumber parameter is
	 *                                        negative</li>
	 *                                        </ul>
	 */
	public static short toBytes(short tagClass, boolean isConstructed, short tagNumber, byte[] outArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (outArray == null)
			throw new NullPointerException();

		if (tagClass > BER_TAG_CLASS_MASK_PRIVATE || tagClass < BER_TAG_CLASS_MASK_UNIVERSAL || tagNumber < 0)
			throw new TLVException(TLVException.INVALID_PARAM);

		if (tagNumber >= 32767)
			throw new TLVException(TLVException.ILLEGAL_SIZE);

		if (outArray.length < bOff)
			throw new ArrayIndexOutOfBoundsException();

		if (tagNumber < 0x1F) {
			byte tag = 0;
			tag |= (((tagClass & 0x03) << 6) & 0xFF);
			tag |= ((isConstructed ? 0x20 : 0x00) & 0xFF);
			tag |= ((tagNumber & 0x1F) & 0xFF);
			outArray[bOff] = tag;
			return 1;
		} else {
			byte tag = 0;
			tag |= (((tagClass & 0x03) << 6) & 0xFF);
			tag |= ((isConstructed ? 0x20 : 0x00) & 0xFF);
			tag |= ((0x1F) & 0xFF);
			outArray[bOff] = tag;

			short byteCounter = 0;
			short tagBytesTester = tagNumber;
			do {
				buffer[byteCounter++] = (byte) ((byte) (tagBytesTester & 0x7F) | 0x80);
				tagBytesTester >>= 7;
			} while (tagBytesTester != 0);

			for (int byteOffset = 0; byteOffset < byteCounter; byteOffset++) {
				outArray[bOff + (byteCounter - byteOffset)] = buffer[byteOffset];
			}
			outArray[bOff + byteCounter] &= 0x7F; // Mask last bit
			return (short) (1 + byteCounter);
		}
	}

	/**
	 * Reads the length of the tag.
	 *
	 * @param berTagArray input byte array containing the BER Tag representation
	 * @param bOff        offset within byte array containing first byte
	 * @return size of BER Tag in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if berTagArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        size of the BER Tag is greater than
	 *                                        the maximum Tag size supported</li>
	 *                                        <li>
	 *                                        TLVException.TAG_SIZE_GREATER_THAN_127
	 *                                        if the size of the BER Tag is >
	 *                                        127.</li>
	 *                                        <li>TLVException.MALFORMED_TAG if tag
	 *                                        representation in the byte array is
	 *                                        malformed</li>
	 *                                        </ul>
	 */
	public static short size(byte[] berTagArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTagArray == null)
			throw new NullPointerException();

		short tagOff = bOff;
		short length = (short) berTagArray.length;
		byte tag = berTagArray[tagOff++];
		if ((tag & 0x1f) == 0x1f) {
			while ((berTagArray[tagOff] & 0x80) != 0) {
				tagOff++;
				if (tagOff - bOff > length) {
					throw new ArrayIndexOutOfBoundsException();
				}
			}
			tagOff++;
			if (tagOff - bOff > length) {
				throw new ArrayIndexOutOfBoundsException();
			}
		}
		short tagLen = (short) (tagOff - bOff);
		if (tagLen > 4)
			throw new TLVException(TLVException.ILLEGAL_SIZE);
		return tagLen;
	}

	/**
	 * Returns the tag number part of the BER Tag from its representation in the
	 * specified byte array
	 *
	 * @param berTagArray input byte array
	 * @param bOff        offset within byte array containing first byte
	 * @return the BER Tag tag number
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if berTagArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        size of the BER Tag is greater than
	 *                                        the maximum Tag size supported</li>
	 *                                        <li>
	 *                                        TLVException.TAG_NUMBER_GREATER_THAN_32767
	 *                                        if the tag number is > 32767.</li>
	 *                                        <li>TLVException.MALFORMED_TAG if tag
	 *                                        representation in the byte array is
	 *                                        malformed.</li>
	 *                                        </ul>
	 */
	public static short tagNumber(byte[] berTagArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTagArray == null)
			throw new TLVException(TLVException.EMPTY_TAG);

		short tagOff = bOff;
		short tag = berTagArray[tagOff++];
		if ((tag & 0x1f) == 0x1f) {
			tag = 0;
			if (((berTagArray[tagOff] & 0x80) == 0x80) && //
					((berTagArray[tagOff + 1] & 0x80) == 0x80) && //
					((berTagArray[tagOff + 2] & 0x80) == 0x80)) {
				throw new TLVException(TLVException.TAG_NUMBER_GREATER_THAN_32767);
			} else if (((berTagArray[tagOff] & 0x80) == 0x80) && //
					((berTagArray[tagOff + 1] & 0x80) == 0x80) && //
					((berTagArray[tagOff + 2] & 0x80) == 0x00)) {
				if ((berTagArray[tagOff] & 0x7E) != 0x00)
					throw new TLVException(TLVException.TAG_NUMBER_GREATER_THAN_32767);

				tag = (short) (((berTagArray[tagOff] & 0x01) << 14) | //
						((berTagArray[tagOff + 1] & 0x7F) << 7) | //
						((berTagArray[tagOff + 2] & 0x7F) << 0));
			} else if (((berTagArray[tagOff] & 0x80) == 0x80) && //
					((berTagArray[tagOff + 1] & 0x80) == 0x00)) {
				tag = (short) (((berTagArray[tagOff] & 0x7F) << 7) | //
						((berTagArray[tagOff + 1] & 0x7F) << 0));
			}
			if (((berTagArray[tagOff] & 0x80) == 0x00)) {
				tag = (short) ((berTagArray[tagOff] & 0x7F) << 0);
			}
		} else {
			tag = (short) (tag & 0x1F);
		}
		return tag;
	}

	/**
	 * Returns the tag class part of the BER Tag from its representation in the
	 * specified byte array
	 *
	 * @param berTagArray input byte array
	 * @param bOff        offset within byte array containing first byte
	 * @return the BER Tag class. One of the BER_TAG_CLASS_MASK_*.. constants
	 *         defined above. See BER_TAG_CLASS_MASK_APPLICATION.
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if berTagArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.MALFORMED_TAG if tag
	 *                                        representation in the byte array is
	 *                                        malformed.</li>
	 *                                        </ul>
	 */
	public static byte tagClass(byte[] berTagArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {
		if (berTagArray == null)
			throw new TLVException(TLVException.EMPTY_TAG);
		byte tagClass = (byte) ((berTagArray[bOff] & 0xC0) >>> 6);
		return tagClass;
	}

	/**
	 * Checks if the input data is a well-formed BER Tag representation
	 *
	 * @param berTagArray input byte array
	 * @param bOff        offset within byte array containing first byte
	 * @return true if input data is a well formed BER Tag structure of tag size
	 *         equal to or less than the supported maximum size, false otherwise
	 */
	public static boolean verifyFormat(byte[] berTagArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException {
		try {
			short tagLen = size(berTagArray, bOff);
			if (tagLen >= 1)
				return true;
			return false;
		} catch (TLVException ex) {
			return false;
		}
	}

	/**
	 * Returns the constructed flag part of the BER Tag from its representation in
	 * the specified byte array
	 *
	 * @param berTagArray input byte array
	 * @param bOff        offset within byte array containing first byte
	 * @return true if constructed, false if primitive
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if berTagArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.MALFORMED_TAG if tag
	 *                                        representation in the byte array is
	 *                                        malformed.</li>
	 *                                        </ul>
	 */
	public static boolean isConstructed(byte[] berTagArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {
		if (berTagArray == null)
			throw new TLVException(TLVException.EMPTY_TAG);

		boolean bitConstructed = ((berTagArray[bOff] & 0x20) == 0x20);
		if (bitConstructed)
			return BER_TAG_TYPE_CONSTRUCTED;
		else
			return BER_TAG_TYPE_PRIMITIVE;
	}

	/**
	 * Abstract init method. (Re-)Initialize this BERTag object from the binary
	 * representation in the byte array. All implementations must support tag
	 * numbers up to 0x3FFF.
	 *
	 * @param bArray the byte array containing the binary representation
	 * @param bOff   the offset within bArray where the tag binary begins
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if bArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        tag number requested is larger than
	 *                                        the supported maximum size</li>
	 *                                        <li>TLVException.MALFORMED_TAG if tag
	 *                                        representation in the byte array is
	 *                                        malformed</li>
	 *                                        </ul>
	 */
	public abstract void init(byte[] bArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException;

	/**
	 * Returns the byte size required to represent this tag structure
	 *
	 * @return size of BER Tag in bytes
	 * @throws TLVException with the following reason codes:
	 *                      TLVException.TAG_SIZE_GREATER_THAN_127 if the size of
	 *                      the BER Tag is > 127. TLVException.EMPTY_TAG if the BER
	 *                      Tag is empty.
	 */
	public byte size() throws TLVException {
		if (tagBytes == null)
			throw new TLVException(TLVException.EMPTY_TAG);
		if (tagBytes.length > 127)
			throw new TLVException(TLVException.TAG_SIZE_GREATER_THAN_127);
		return (byte) tagBytes.length;
	}

	/**
	 * Writes the representation of this BER tag structure to the byte array
	 *
	 * @param outBuf  the byteArray where the BER tag is written
	 * @param bOffset offset within outBuf where BER tag value starts
	 * @return size of BER Tag in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outBuf is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.EMPTY_TAG if the BER
	 *                                        Tag is empty.</li>
	 *                                        </ul>
	 */
	public short toBytes(byte[] outBuf, short bOffset)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {
		if (outBuf == null)
			throw new NullPointerException();
		if (tagBytes == null)
			throw new TLVException(TLVException.EMPTY_TAG);
		if (outBuf.length < bOffset + tagBytes.length)
			throw new ArrayIndexOutOfBoundsException();
		return Util.arrayCopy(tagBytes, (short) 0, outBuf, bOffset, (short) tagBytes.length);
	}

	/**
	 * Returns the tag number part of this BER Tag structure
	 *
	 * @return the BER Tag tag number
	 * @throws TLVException with the following reason codes:
	 *                      <ul>
	 *                      <li>TLVException.TAG_NUMBER_GREATER_THAN_32767 if the
	 *                      tag number is > 32767.</li>
	 *                      <li>TLVException.EMPTY_TAG if the BER Tag is empty.</li>
	 *                      </ul>
	 */
	public short tagNumber() throws TLVException {
		return tagNumber(tagBytes, (short) 0);
	}

	/**
	 * Used to query if this BER tag structure is constructed
	 *
	 * @return true if constructed, false if primitive
	 * @throws TLVException with the following reason codes: TLVException.EMPTY_TAG
	 *                      if the BER Tag is empty.
	 */
	public boolean isConstructed() throws TLVException {
		return isConstructed(tagBytes, (short) 0);
	}

	/**
	 * Returns the tag class part of this BER Tag structure
	 *
	 * @return the BER Tag class. One of the BER_TAG_CLASS_MASK_*.. constants
	 *         defined above. See BER_TAG_CLASS_MASK_APPLICATION.
	 * @throws TLVException with the following reason codes:
	 *                      <ul>
	 *                      <li>TLVException.EMPTY_TAG if the BER Tag is empty.</li>
	 *                      </ul>
	 */
	public byte tagClass() throws TLVException {
		return tagClass(tagBytes, (short) 0);
	}

	/**
	 * Compares this BER Tag with another. Note that this method does not throw
	 * exceptions. If the parameter otherTag is null, the method returns false
	 *
	 * @param otherTag
	 * @return true if the tag data encapsulated are equal, false otherwise
	 */
	public boolean equals(BERTag otherTag) {
		if (otherTag == null)
			return false;
		if (tagBytes.length != otherTag.tagBytes.length)
			return false;
		if (Util.arrayCompare(tagBytes, (short) 0, otherTag.tagBytes, (short) 0, (short) tagBytes.length) != 0)
			return false;
		return true;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		try {
			for (short idx = 0; idx < tagBytes.length; idx++)
				sb.append(String.format("%02X", tagBytes[idx]));
			sb.append(" [");
			sb.append(isConstructed() ? "Constructed" : "Primitive");
			sb.append(",");
			switch (tagClass()) {
			default:
			case BER_TAG_CLASS_MASK_UNIVERSAL:
				sb.append("Universal");
				break;
			case BER_TAG_CLASS_MASK_APPLICATION:
				sb.append("Application");
				break;
			case BER_TAG_CLASS_MASK_CONTEXT_SPECIFIC:
				sb.append("Context");
				break;
			case BER_TAG_CLASS_MASK_PRIVATE:
				sb.append("Private");
				break;
			}
			sb.append("]");
		} catch (TLVException | Exception ex) {
			System.err.println(ex.getMessage());
		}
		return sb.toString();
	}

}
