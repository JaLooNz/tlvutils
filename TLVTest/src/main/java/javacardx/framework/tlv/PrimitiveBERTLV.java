package javacardx.framework.tlv;

import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

import com.jaloonz.tlv.utils.JCEnvironmentExceptions;
import com.jaloonz.tlv.utils.LogHelper;
import com.jaloonz.tlv.utils.TLVHelper;

import javacardx.framework.Util;

/**
 * The PrimitiveBERTLV class encapsulates a primitive BER TLV structure. It
 * extends the generic BERTLV class. The rules on the allowed encoding of the
 * Tag, length and value fields is based on the ASN.1 BER encoding rules ISO/IEC
 * 8825-1:2002.
 * <p/>
 * The PrimitiveBERTLV class only supports encoding of the length(L) octets in
 * definite form. The value(V) field which encodes the contents octets are
 * merely viewed as a series of bytes.
 * <p/>
 * Every PrimitiveBERTLV has a capacity which represents the allocated internal
 * buffer to represent the Value of this TLV object. As long as the number of
 * bytes required to represent the Value of the TLV object does not exceed the
 * capacity, it is not necessary to allocate additional internal buffer space.
 * If the internal buffer overflows, and the implementation supports automatic
 * expansion which might require new data allocation and possibly old
 * data/object deletion, it is automatically made larger. Otherwise a
 * TLVException is thrown.
 * <p/>
 * The {@link BERTLV} class and the subclasses {@link ConstructedBERTLV} and
 * {@link PrimitiveBERTLV}, also provide static methods to parse or edit a TLV
 * structure representation in a byte array.
 */
public class PrimitiveBERTLV extends BERTLV {

	public byte[] mData;
	public short mDataSize = 0;

	/**
	 * Constructor creates an empty PrimitiveBERTLV object capable of encapsulating
	 * a Primitive BER TLV structure. The initial capacity is specified by the
	 * numValueBytes argument.
	 * 
	 * @param numValueBytes is the number of Value bytes to allocate
	 * @throws TLVException with the following reason codes:
	 *                      TLVException.INVALID_PARAM if numValueBytes parameter is
	 *                      negative or larger than the maximum capacity supported
	 *                      by the implementation.
	 */
	public PrimitiveBERTLV(short numValueBytes) throws TLVException {
		resizeDataBuffer(numValueBytes);
	}

	/**
	 * Resizes data array.
	 * 
	 * @param numValueBytes is the number of Value bytes to allocate
	 * @return true if capacity is sufficient, false otherwise
	 */
	private boolean resizeDataBuffer(short numValueBytes) {

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
	public short init(byte[] bArray, short bOff, short bLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (bArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (bOff + bLen > bArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		short bOffset = bOff;
		short tagLen, lenLen, dataLen = 0;

		mTag = BERTag.getInstance(bArray, bOffset);
		tagLen = mTag.size();
		bOffset += tagLen;

		dataLen = getLength(bArray, bOffset);
		lenLen = TLVHelper.getLengthLength(bArray, bOffset);
		bOffset += lenLen;

		if (bOffset > bArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		// Allow to initialise PrimitiveBERTLV, ignoring remaining
		// data (i.e. capture only the TLV itself).
		return init((PrimitiveBERTag) mTag, bArray, bOffset, dataLen);
	}

	/**
	 * (Re-)Initializes this PrimitiveBERTLV object with the input tag, length and
	 * data. Note that a reference to the BER Tag object is retained by this object.
	 * A change in the BER Tag object contents affects this TLV instance.
	 * <p/>
	 * If this primitive TLV object is empty, the initial capacity of this
	 * PrimitiveBERTLV is set to the value of the vLen argument.
	 * <p/>
	 * Note: If vOff+vLen is greater than vArray.length, the length of the vArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param tag    a BERTag object
	 * @param vArray the byte array containing length bytes of TLV value
	 * @param vOff   offset within the vArray byte array where data begins
	 * @param vLen   byte length of the value data in vArray
	 * @return the resulting size of this TLV if represented in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        array length parameter is negative
	 * @throws NullPointerException           if either tag or vArray parameter is
	 *                                        null
	 * @throws TLVException                   with the following reason codes:
	 *                                        TLVException.INSUFFICIENT_STORAGE if
	 *                                        the required capacity is not available
	 *                                        and the implementation does not
	 *                                        support automatic expansion.
	 */
	public short init(PrimitiveBERTag tag, byte[] vArray, short vOff, short vLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (tag == null || vArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (vOff + vLen > vArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		this.mTag = tag;
		return appendValue(vArray, vOff, vLen);
	}

	/**
	 * Appends the specified data to the end of this Primitive BER TLV object.
	 * <p/>
	 * Note: If vOff+vLen is greater than vArray.length, the length of the vArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param vArray the byte array containing length bytes of TLV value
	 * @param vOff   offset within the vArray byte array where data begins
	 * @param vLen   the byte length of the value in the input vArray
	 * @return the resulting size of this if represented in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        length parameter is negative
	 * @throws NullPointerException           if vArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        TLVException.INSUFFICIENT_STORAGE if
	 *                                        the required capacity is not available
	 *                                        and the implementation does not
	 *                                        support automatic expansion
	 *                                        TLVException.EMPTY_TLV if this
	 *                                        PrimitiveBERTLV object is empty.
	 */
	public short appendValue(byte[] vArray, short vOff, short vLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (mTag == null || mData == null)
			TLVException.throwIt(TLVException.EMPTY_TLV);

		if (vArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (vOff + vLen > vArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		if (!resizeDataBuffer((short) (mDataSize + vLen)))
			TLVException.throwIt(TLVException.INSUFFICIENT_STORAGE);

		Util.arrayCopyNonAtomic(vArray, vOff, mData, mDataSize, vLen);
		mDataSize += vLen;

		return mDataSize;
	}

	/**
	 * Replaces the specified data in place of the current value of this Primitive
	 * BER TLV object.
	 * <p/>
	 * Note: If vOff+vLen is greater than vArray.length, the length of the vArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param vArray the byte array containing length bytes of TLV value
	 * @param vOff   offset within the vArray byte array where data begins
	 * @param vLen   the byte length of the value in the input vArray
	 * @return the resulting size of this if represented in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        length parameter is negative
	 * @throws NullPointerException           if vArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.INSUFFICIENT_STORAGE
	 *                                        if the required capacity is not
	 *                                        available and the implementation does
	 *                                        not support automatic expansion</li>
	 *                                        <li>TLVException.EMPTY_TLV if this
	 *                                        PrimitiveBERTLV object is empty.</li>
	 *                                        </ul>
	 */
	public short replaceValue(byte[] vArray, short vOff, short vLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (mTag == null || mData == null)
			TLVException.throwIt(TLVException.EMPTY_TLV);

		if (vArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (vOff + vLen > vArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		if (!resizeDataBuffer((short) (vLen)))
			TLVException.throwIt(TLVException.INSUFFICIENT_STORAGE);

		Util.arrayCopyNonAtomic(vArray, vOff, mData, (short) 0, vLen);
		mDataSize = vLen;

		return mDataSize;
	}

	/**
	 * Writes the value (V) part of this Primitive BER TLV object into the output
	 * buffer. Returns the length of data written to tlvValue output array
	 * 
	 * @param tlvValue the output byte array
	 * @param tOff     offset within the tlvValue byte array where output data
	 *                 begins
	 * @return the byte length of data written to tlvValue output array
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if tlvValue is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>
	 *                                        TLVException.TLV_SIZE_GREATER_THAN_32767
	 *                                        if the size of the Primitive BER TLV
	 *                                        is > 32767</li>
	 *                                        <li>TLVException.EMPTY_TLV if this
	 *                                        PrimitiveBERTLV object is empty.</li>
	 *                                        </ul>
	 */
	public short getValue(byte[] tlvValue, short tOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (tlvValue == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (tOff + mDataSize > tlvValue.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		Util.arrayCopyNonAtomic(mData, (short) 0, tlvValue, tOff, mDataSize);
		return mDataSize;
	}

	/**
	 * Returns the offset into the specified input byte array of the value (V) part
	 * of the BER TLV structure representation in the input array.
	 * 
	 * @param berTLVArray input byte array
	 * @param bTLVOff     offset within byte array containing the TLV data
	 * @return the offset into the specified input byte array of the value (V) part
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if berTLVArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>
	 *                                        TLVException.TLV_SIZE_GREATER_THAN_32767
	 *                                        if the size of the Primitive BER TLV
	 *                                        is > 32767.</li>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        TLV representation in the input byte
	 *                                        array is not a well-formed primitive
	 *                                        BER TLV structure.</li>
	 *                                        </ul>
	 */
	public static short getValueOffset(byte[] berTLVArray, short bTLVOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTLVArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		short tagLen, lenLen;
		tagLen = BERTag.size(berTLVArray, bTLVOff);
		lenLen = TLVHelper.getLengthLength(berTLVArray, (short) (bTLVOff + tagLen));
		return (short) (bTLVOff + tagLen + lenLen);
	}

	/**
	 * Writes a primitive TLV representation to the specified byte array using as
	 * input a Primitive BER tag representation in a byte array and a value
	 * representation in another byte array.
	 * <p/>
	 * Note: If vOff+vLen is greater than valueArray.length, the length of the
	 * valueArray array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param berTagArray input byte array
	 * @param berTagOff   offset within byte array containing first byte of tag
	 * @param valueArray  input byte array containing primitive value
	 * @param vOff        offset within byte array containing the first byte of
	 *                    value
	 * @param vLen        length in bytes of the value component of the TLV
	 * @param outBuf      output byte array
	 * @param bOff        offset within byte array output data begins
	 * @return the byte length written to the output array
	 * @throws ArrayIndexOutOfBoundsException if accessing the input or output
	 *                                        arrays would cause access of data
	 *                                        outside array bounds, or if any of the
	 *                                        array offset or array length
	 *                                        parameters is negative
	 * @throws NullPointerException           if berTagArray or valueArray or outBuf
	 *                                        is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>
	 *                                        TLVException.TLV_SIZE_GREATER_THAN_32767
	 *                                        if the size of the resulting Primitive
	 *                                        BER TLV is > 32767.</li>
	 *                                        <li>TLVException.MALFORMED_TAG if the
	 *                                        tag representation in the byte array
	 *                                        is not a well-formed constructed array
	 *                                        tag.</li>
	 *                                        </ul>
	 */
	public static short toBytes(byte[] berTagArray, short berTagOff, byte[] valueArray, short vOff, short vLen,
			byte[] outBuf, short bOff) throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTagArray == null || valueArray == null || outBuf == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (vOff + vLen > valueArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		short tagLen;
		short outBufOffset = bOff;
		tagLen = BERTag.size(berTagArray, berTagOff);
		outBufOffset += Util.arrayCopyNonAtomic(berTagArray, berTagOff, outBuf, bOff, tagLen);

		if (vLen < 128) {
			outBuf[outBufOffset++] = (byte) vLen;
		} else if (vLen < 256) {
			outBuf[outBufOffset++] = (byte) 0x81;
			outBuf[outBufOffset++] = (byte) vLen;
		} else if (vLen < 65536) {
			outBuf[outBufOffset++] = (byte) 0x82;
			outBuf[outBufOffset++] = (byte) ((vLen >> 8) & 0xFF);
			outBuf[outBufOffset++] = (byte) (vLen & 0xFF);
		} else {
			outBuf[outBufOffset++] = (byte) 0x83;
			outBuf[outBufOffset++] = (byte) ((vLen >> 16) & 0xFF);
			outBuf[outBufOffset++] = (byte) ((vLen >> 8) & 0xFF);
			outBuf[outBufOffset++] = (byte) (vLen & 0xFF);
		}

		outBufOffset += Util.arrayCopyNonAtomic(valueArray, vOff, outBuf, outBufOffset, (short) vLen);
		return (short) (outBufOffset - bOff);
	}

	/**
	 * Appends the specified data to the end of the Primitive TLV representation in
	 * the specified byte array. Note that this method is only applicable to a
	 * primitive TLV representation, otherwise an exception is thrown.
	 * <p/>
	 * Note: If vOff+vLen is greater than vArray.length, the length of the vArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param berTLVArray input byte array
	 * @param bTLVOff     offset within byte array containing the TLV data
	 * @param vArray      the byte array containing value to be appended
	 * @param vOff        offset within the vArray byte array where the data begins
	 * @param vLen        the byte length of the value in the input vArray
	 * @return the resulting size of this if represented in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input arrays would
	 *                                        cause access of data outside array
	 *                                        bounds, or if any of the array offset
	 *                                        or array length parameters is negative
	 * @throws NullPointerException           if berTLVArray or vArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>
	 *                                        TLVException.TLV_SIZE_GREATER_THAN_32767
	 *                                        if the size of the resulting Primitive
	 *                                        BER TLV is > 32767.</li>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        TLV representation in the input byte
	 *                                        array is not a well-formed primitive
	 *                                        BER TLV structure</li>
	 *                                        </ul>
	 */
	public static short appendValue(byte[] berTLVArray, short bTLVOff, byte[] vArray, short vOff, short vLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTLVArray == null || vArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		if (vOff + vLen > vArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		BERTLV tlv = BERTLV.getInstance(berTLVArray, bTLVOff, bTLVOff);
		if (tlv.mTag == null || tlv.mTag.isConstructed())
			TLVException.throwIt(TLVException.MALFORMED_TLV);

		PrimitiveBERTLV ptlv = (PrimitiveBERTLV) tlv;
		ptlv.appendValue(vArray, vOff, vLen);
		return ptlv.toBytes(berTLVArray, bTLVOff);
	}

	@Override
	public String getDescription(short level) {
		StringBuilder sb = new StringBuilder();
		sb.append(LogHelper.drawLevel(level));
		if (mTag != null) {
			sb.append(String.format("T=%s, L=%d, V=%s\n", mTag.toString(), mDataSize,
					Hex.encodeHexString(Arrays.copyOf(mData, mDataSize), false)));
		} else {
			sb.append("Invalid TLV");
		}
		return sb.toString();
	}

	@Override
	protected short writeData(byte[] outArray, short bOff) {
		return Util.arrayCopy(mData, (short) 0, outArray, bOff, mDataSize);
	}

	@Override
	protected short getDataLength() {
		return mDataSize;
	}
}
