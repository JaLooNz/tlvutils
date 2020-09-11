package javacardx.framework.tlv;

import javacardx.framework.Util;

/**
 * The abstract BERTLV class encapsulates a BER TLV structure. The rules on the
 * allowed encoding of the Tag, length and value fields are based on the ASN.1
 * BER encoding rules ISO/IEC 8825-1:2002.
 * <p/>
 * The BERTLV class and the subclasses - ConstructedBERTLV and PrimitiveBERTLV
 * only support encoding of the length(L) octets in definite form. These classes
 * do not provide support for the encoding rules of the contents octets of the
 * value(V) field as described in ISO/IEC 8825-1:2002. The BERTLV class and the
 * subclasses - ConstructedBERTLV and PrimitiveBERTLV also provide static
 * methods to parse/edit a TLV structure representation in a byte array.
 */
public abstract class BERTLV {

	protected BERTag mTag;
	protected byte[] mData;
	protected short mDataSize = 0;
	protected static final boolean SUPPORT_EXPANSION = true;
	protected static final byte ASN1_EOC = 0x00;

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
			throw new ArrayIndexOutOfBoundsException();

		short bOffset = bOff;
		short tagLen, lenLen, dataLen = 0;
		boolean isConstructed, isSequentialTLVs;

		tagLen = BERTag.size(bArray, bOffset);
		isConstructed = BERTag.isConstructed(bArray, bOffset);
		bOffset += tagLen;

		dataLen = getLength(bArray, bOffset);
		lenLen = getLengthLength(bArray, bOffset);
		bOffset += lenLen;

		bOffset += dataLen;
		
//		if (tagLen+lenLen+dataLen != bLen)
//			isSequentialTLVs = true;
//		else 
//			isSequentialTLVs = false;

		BERTLV tlv = null;
//		if (isSequentialTLVs) {
//			
//		}else 
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
			throw new NullPointerException();

		if (mTag == null || mData == null)
			throw new TLVException(TLVException.EMPTY_TLV);

		short outBufOffset = bOff;
		outBufOffset += mTag.toBytes(outBuf, outBufOffset);

		if (mData.length < 128) {
			outBuf[outBufOffset++] = (byte) mData.length;
		} else if (mData.length < 256) {
			outBuf[outBufOffset++] = (byte) 0x81;
			outBuf[outBufOffset++] = (byte) mData.length;
		} else if (mData.length < 65536) {
			outBuf[outBufOffset++] = (byte) 0x82;
			outBuf[outBufOffset++] = (byte) ((mData.length >> 8) & 0xFF);
			outBuf[outBufOffset++] = (byte) (mData.length & 0xFF);
		} else {
			outBuf[outBufOffset++] = (byte) 0x83;
			outBuf[outBufOffset++] = (byte) ((mData.length >> 16) & 0xFF);
			outBuf[outBufOffset++] = (byte) ((mData.length >> 8) & 0xFF);
			outBuf[outBufOffset++] = (byte) (mData.length & 0xFF);
		}

		outBufOffset += Util.arrayCopyNonAtomic(mData, (short) 0, outBuf, outBufOffset, (short) mData.length);

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

		if (mData == null)
			throw new TLVException(TLVException.EMPTY_TLV);

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

		if (mData == null)
			throw new TLVException(TLVException.EMPTY_TLV);

		if (mData.length > 32767)
			throw new TLVException(TLVException.TLV_LENGTH_GREATER_THAN_32767);

		return (short) mData.length;
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

		return (short) (mTag.size() + getLengthLength(mDataSize) + mDataSize);
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
			throw new NullPointerException();

		if (bOff + bLen > berTlvArray.length)
			throw new ArrayIndexOutOfBoundsException();

		try {
			short tlvLen = bOff;
			short tagLen, lenLen, dataLen = 0;

			tagLen = BERTag.size(berTlvArray, tlvLen);
			tlvLen += tagLen;

			if (berTlvArray[tlvLen] >= 0) // 0~7F
				lenLen = (short) (berTlvArray[tlvLen] & 0x7F);
			else
				lenLen = (short) (1 + (berTlvArray[tlvLen] & 0x7F));
			tlvLen += lenLen;

			dataLen = getLength(berTlvArray, tlvLen);
			tlvLen += dataLen;

			if (bOff + tlvLen <= bLen) {
				throw new TLVException(TLVException.MALFORMED_TLV);
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
			throw new NullPointerException();

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
			throw new NullPointerException();

		if (berTLVArray.length < bOff) {
			throw new TLVException(TLVException.MALFORMED_TLV);
		}

		short offset = bOff;
		byte len = berTLVArray[offset++];
		if (len >= 0) // 0~7F
		{
			return (short) (len & 0xff);
		} else if (len == (byte) 0x81) {
			if (berTLVArray.length < bOff + 1) {
				throw new TLVException(TLVException.MALFORMED_TLV);
			}
			return (short) (berTLVArray[offset] & 0xff);
		} else if (len == (byte) 0x82) {
			if (berTLVArray.length < bOff + 2) {
				throw new TLVException(TLVException.MALFORMED_TLV);
			}
			short val = Util.getShort(berTLVArray, offset);
			if (val < 0) {
				throw new TLVException(TLVException.TLV_LENGTH_GREATER_THAN_32767);
			}
			return val;
		} else {
			throw new TLVException(TLVException.TLV_LENGTH_GREATER_THAN_32767);
		}
	}

	/**
	 * Gets the data length required to represent value.
	 * 
	 * @param berTLVArray input byte array
	 * @param bOff        offset within byte array containing the tlv length first
	 *                    byte
	 * @return Data length required to represent value
	 */
	protected static short getLengthLength(byte[] berTLVArray, short bOff) {
		if (berTLVArray[bOff] >= 0) // 0~7F
			return 1;
		else
			return (short) (1 + (berTLVArray[bOff] & 0x7F));
	}

	/**
	 * Gets the data length required to represent value.
	 * 
	 * @param bLength Value length.
	 * @return Data length required to represent value
	 */
	protected static short getLengthLength(short bLength) {
		if (bLength < 128) {
			return 1;
		} else if (bLength < 256) {
			return 2;
		} else if (bLength < 65536) {
			return 3;
		} else {
			return 4;
		}
	}

	/**
	 * Resizes data array.
	 * 
	 * @param numValueBytes is the number of Value bytes to allocate
	 * @return true if capacity is sufficient, false otherwise
	 */
	protected boolean resizeDataBuffer(short numValueBytes) {

		if (mData == null) {
			mData = new byte[numValueBytes];
			return true;
		} else if (SUPPORT_EXPANSION) {
			if (mData.length < numValueBytes) {
				byte[] newArray = new byte[numValueBytes];
				Util.arrayCopyNonAtomic(mData, (short) 0, newArray, (short) 0, mDataSize);
				mData = newArray;
			}
			return true;
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return getDescription((short) 0);
	}

	public abstract String getDescription(short level);
	
	public String drawLevel(short level) {

		StringBuilder sb = new StringBuilder();
		short levelDrawer = level;
		while (levelDrawer > 0) {
			if (levelDrawer-- > 1)
				sb.append("    ");
			else
				sb.append("+-- ");
		}
		return sb.toString();
	}
}
