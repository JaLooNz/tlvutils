package javacardx.framework.tlv;

import com.jaloonz.tlv.utils.JCEnvironmentExceptions;
import com.jaloonz.tlv.utils.TLVHelper;

import javacardx.framework.Util;

/**
 * The abstract BERTLV class encapsulates a BER TLV structure. The rules on the
 * allowed encoding of the Tag, length and value fields are based on the ASN.1
 * BER encoding rules ISO/IEC 8825-1:2002.
 * <p/>
 * The {@link BERTLV} class and the subclasses - {@link ConstructedBERTLV} and
 * {@link PrimitiveBERTLV} only support encoding of the length(L) octets in
 * definite form. These classes do not provide support for the encoding rules of
 * the contents octets of the value(V) field as described in ISO/IEC
 * 8825-1:2002.
 * <p/>
 * The {@link BERTLV} class and the subclasses - {@link ConstructedBERTLV} and
 * {@link PrimitiveBERTLV} also provide static methods to parse/edit a TLV
 * structure representation in a byte array.
 */
public abstract class BERTLV {

	protected BERTag mTag;
	protected static final boolean SUPPORT_EXPANSION = true;

	/**
	 * Constructor creates an empty BERTLV object capable of encapsulating a BER TLV
	 * structure.
	 */
	protected BERTLV() {

	}

	/**
	 * Abstract init method. (Re-)Initializes this BERTLV using the input byte data.
	 * If this is an empty TLV object the initial capacity of this BERTLV is set
	 * based on the size of the input TLV data structure.
	 * <p/>
	 * Note: If bOff+bLen is greater than bArray.length, the length of the bArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param bArray input byte array
	 * @param bOff   offset within byte array containing the TLV data
	 * @param bLen   byte length of input data
	 * @return the resulting size of this TLV if represented in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        array length parameter is negative
	 * @throws NullPointerException           if bArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.INSUFFICIENT_STORAGE
	 *                                        if the required capacity is not
	 *                                        available and the implementation does
	 *                                        not support automatic expansion.</li>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        input data is not a well-formed BER
	 *                                        TLV or the input data represents a
	 *                                        primitive BER TLV structure and this
	 *                                        is a ConstructedBERTLV object or the
	 *                                        input data represents a constructed
	 *                                        BER TLV structure and this is a
	 *                                        PrimiitveBERTLV object.</li>
	 *                                        </ul>
	 */
	public abstract short init(byte[] bArray, short bOff, short bLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException;

	/**
	 * Creates the BERTLV using the input binary data. The resulting BER TLV object
	 * may be a primitive or a constructed TLV object. The object must be cast to
	 * the correct sub-class: ConstructedBERTLV or PrimitiveBERTLV to access the
	 * specialized API.
	 * <p/>
	 * The init( byte[] bArray, short bOff, short bLen ) methods of the appropriate
	 * BERTLV classes will be used to initialize the created TLV object.
	 * <p/>
	 * Note: If bOff+bLen is greater than bArray.length, the length of the bArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param bArray input byte array
	 * @param bOff   offset within byte array containing the tlv data
	 * @param bLen   byte length of input data
	 * @return BERTLV
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        array length parameter is negative
	 * @throws NullPointerException           if bArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        TLV structure requested is larger than
	 *                                        the supported maximum size</li>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        input data is not a well-formed BER
	 *                                        TLV.</li>
	 *                                        </ul>
	 */
	public static BERTLV getInstance(byte[] bArray, short bOff, short bLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (bOff + bLen > bArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		short bOffset = bOff;
		short tagLen, lenLen, dataLen = 0;
		boolean isConstructed;

		tagLen = BERTag.size(bArray, bOffset);
		isConstructed = BERTag.isConstructed(bArray, bOffset);
		bOffset += tagLen;

		dataLen = getLength(bArray, bOffset);
		lenLen = TLVHelper.getLengthLength(bArray, bOffset);
		bOffset += lenLen;

		bOffset += dataLen;

		BERTLV tlv = null;
		if (isConstructed) {
			tlv = new ConstructedBERTLV((short) 0);
		} else {
			tlv = new PrimitiveBERTLV(dataLen);
		}

		tlv.init(bArray, bOff, dataLen);
		return tlv;
	}

	/**
	 * Writes this TLV structure to the specified byte array.
	 * 
	 * @param outBuf output byte array
	 * @param bOff   offset within byte array output data begins
	 * @return the byte length written to the output array
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outBuf is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>
	 *                                        TLVException.TLV_SIZE_GREATER_THAN_32767
	 *                                        if the size of the BER TLV is >
	 *                                        32767.</li>
	 *                                        <li>TLVException.EMPTY_TLV if the
	 *                                        BERTLV object is empty.</li>
	 *                                        </ul>
	 */
	public short toBytes(byte[] outBuf, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (outBuf == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (mTag == null)
			TLVException.throwIt(TLVException.EMPTY_TLV);

		short tagLen, dataLen;
		short outBufOffset = bOff;
		tagLen = mTag.toBytes(outBuf, outBufOffset);
		outBufOffset += tagLen;

		dataLen = getLength();
		if (dataLen < 128) {
			outBuf[outBufOffset++] = (byte) dataLen;
		} else if (dataLen < 256) {
			outBuf[outBufOffset++] = (byte) 0x81;
			outBuf[outBufOffset++] = (byte) dataLen;
		} else if (dataLen < 65536) {
			outBuf[outBufOffset++] = (byte) 0x82;
			outBuf[outBufOffset++] = (byte) ((dataLen >> 8) & 0xFF);
			outBuf[outBufOffset++] = (byte) (dataLen & 0xFF);
		} else {
			outBuf[outBufOffset++] = (byte) 0x83;
			outBuf[outBufOffset++] = (byte) ((dataLen >> 16) & 0xFF);
			outBuf[outBufOffset++] = (byte) ((dataLen >> 8) & 0xFF);
			outBuf[outBufOffset++] = (byte) (dataLen & 0xFF);
		}

		outBufOffset = writeData(outBuf, outBufOffset);

		return (short) (outBufOffset - bOff);
	}

	/**
	 * Returns this value of the TLV object's Tag component
	 * 
	 * @return the Tag for this BERTLV object
	 * @throws TLVException with the following reason codes:
	 *                      <ul>
	 *                      <li>TLVException.EMPTY_TLV if the BERTLV object is
	 *                      empty.</li>
	 *                      </ul>
	 */
	public BERTag getTag() throws TLVException {

		if (mTag == null)
			TLVException.throwIt(TLVException.EMPTY_TLV);

		return mTag;
	}

	/**
	 * Returns the value of this TLV object's Length component
	 * 
	 * @return Value of this TLV object's Length component
	 * @throws TLVException with the following reason codes:
	 *                      <ul>
	 *                      <li>TLVException.TLV_LENGTH_GREATER_THAN_32767 if the
	 *                      value of the Length component is > 32767.</li>
	 *                      <li>TLVException.EMPTY_TLV if the BERTLV object is
	 *                      empty.</li>
	 *                      </ul>
	 */
	public short getLength() throws TLVException {

		if (mTag == null)
			TLVException.throwIt(TLVException.EMPTY_TLV);

		short dataLen = getDataLength();
		if (dataLen > 32767)
			TLVException.throwIt(TLVException.TLV_LENGTH_GREATER_THAN_32767);

		return (short) dataLen;
	}

	/**
	 * Returns the number of bytes required to represent this TLV structure
	 * 
	 * @return the byte length of the TLV
	 * @throws TLVException with the following reason codes:
	 *                      <ul>
	 *                      <li>TLVException.TLV_SIZE_GREATER_THAN_32767 if the size
	 *                      of TLV structure is > 32767.</li>
	 *                      <li>TLVException.EMPTY_TLV if the BERTLV object is
	 *                      empty.</li>
	 *                      </ul>
	 */
	public short size() throws NullPointerException, TLVException {

		short dataLen = getLength();
		return (short) (mTag.size() + TLVHelper.getLengthLength(dataLen) + dataLen);
	}

	/**
	 * Checks if the input data is a well-formed BER TLV representation.
	 * <p/>
	 * Note: If bOff+bLen is greater than berTlvArray.length, the length of the
	 * berTlvArray array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param berTlvArray input byte array
	 * @param bOff        offset within byte array containing first byte
	 * @param bLen        byte length of input BER TLV data
	 * @return true if input data is a well formed BER TLV structure, false
	 *         otherwise
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        array length parameter is negative
	 * @throws NullPointerException           if berTlvArray is null
	 */
	public static boolean verifyFormat(byte[] berTlvArray, short bOff, short bLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException {

		if (berTlvArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (bOff + bLen > berTlvArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		try {
			short tlvLen = bOff;
			short tagLen, lenLen, dataLen = 0;

			tagLen = BERTag.size(berTlvArray, tlvLen);
			tlvLen += tagLen;

			lenLen = TLVHelper.getLengthLength(berTlvArray, tlvLen);
			tlvLen += lenLen;

			dataLen = getLength(berTlvArray, tlvLen);
			tlvLen += dataLen;

			if (bOff + tlvLen <= bLen) {
				TLVException.throwIt(TLVException.MALFORMED_TLV);
			}
			return true;
		} catch (TLVException ex) {
			return false;
		}
	}

	/**
	 * Copies the tag component in the TLV representation in the specified input
	 * byte array to the specified output byte array
	 * 
	 * @param berTLVArray input byte array
	 * @param bTLVOff     offset within byte array containing the tlv data
	 * @param berTagArray output Tag byte array
	 * @param bTagOff     offset within byte array where output begins
	 * @return the size of the output BER Tag
	 * @throws ArrayIndexOutOfBoundsException if accessing the input or output array
	 *                                        would cause access of data outside
	 *                                        array bounds, or if either array
	 *                                        offset parameter is negative
	 * @throws NullPointerException           if either berTLVArray or berTagArray
	 *                                        is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.ILLEGAL_SIZE if the
	 *                                        size of the Tag component is >
	 *                                        32767.</li>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        input data is not a well-formed BER
	 *                                        TLV.</li>
	 *                                        </ul>
	 */
	public static short getTag(byte[] berTLVArray, short bTLVOff, byte[] berTagArray, short bTagOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTLVArray == null || berTagArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		short tagLen = BERTag.size(berTLVArray, bTLVOff);
		return Util.arrayCopyNonAtomic(berTLVArray, bTLVOff, berTagArray, bTagOff, tagLen);
	}

	/**
	 * Returns the value of the TLV Structure's Length component in the specified
	 * input byte array
	 * 
	 * @param berTLVArray input byte array
	 * @param bOff        offset within byte array containing the tlv data
	 * @return the length value in the TLV representation in the specified byte
	 *         array
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if berTLVArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>
	 *                                        TLVException.TLV_LENGTH_GREATER_THAN_32767
	 *                                        if the length element(L) > 32767.</li>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        input data is not a well-formed BER
	 *                                        TLV.</li>
	 *                                        </ul>
	 */
	public static short getLength(byte[] berTLVArray, short bOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTLVArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (berTLVArray.length < bOff) {
			TLVException.throwIt(TLVException.MALFORMED_TLV);
		}

		short offset = bOff;
		byte len = berTLVArray[offset++];
		if (len >= 0) // 0~7F
		{
			return (short) (len & 0x7f);
		} else if (len == (byte) 0x81) {
			if (berTLVArray.length < bOff + 1) {
				TLVException.throwIt(TLVException.MALFORMED_TLV);
			}
			return (short) (berTLVArray[offset] & 0xff);
		} else if (len == (byte) 0x82) {
			if (berTLVArray.length < bOff + 2) {
				TLVException.throwIt(TLVException.MALFORMED_TLV);
			}
			short val = Util.getShort(berTLVArray, offset);
			if (val < 0) {
				TLVException.throwIt(TLVException.TLV_LENGTH_GREATER_THAN_32767);
			}
			return val;
		} else {
			TLVException.throwIt(TLVException.TLV_LENGTH_GREATER_THAN_32767);
		}
		return len;
	}

	@Override
	public String toString() {
		return getDescription((short) 0);
	}

	/**
	 * [IMPLEMENTATION-SPECIFIC]
	 * <p/>
	 * Writes TLV data to output array.
	 * 
	 * @param outArray Output array.
	 * @param bOff     Output array offset.
	 * @return Offset of last data byte.
	 */
	protected abstract short writeData(byte[] outArray, short bOff);

	/**
	 * [IMPLEMENTATION-SPECIFIC]
	 * <p/>
	 * Gets data length.
	 * 
	 * @return Data length.
	 */
	protected abstract short getDataLength();

	/**
	 * [IMPLEMENTATION-SPECIFIC]
	 * <p/>
	 * Gets description of contents for {@link BERTLV}.
	 * 
	 * @param level Level of construction.
	 * @return String description of contents.
	 */
	public abstract String getDescription(short level);
}
