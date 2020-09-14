package javacardx.framework.tlv;

import com.jaloonz.tlv.utils.JCEnvironmentExceptions;

/**
 * The SequentialBERTLV class encapsulates a list of sequential BER TLV
 * structure. The rules on the allowed encoding of the Tag, length and value
 * fields is based on the ASN.1 BER encoding rules ISO/IEC 8825-1:2002.
 * <p/>
 * Every SequentialBERTLV has a capacity which represents the size of the
 * allocated internal data structures to reference all the contained BER TLV
 * objects. As long as the number of contained BER TLV objects of the
 * SequentialBERTLV does not exceed the capacity, it is not necessary to
 * allocate new internal data. If the internal buffer overflows, and the
 * implementation supports automatic expansion which might require new data
 * allocation and possibly old data/object deletion, it is automatically made
 * larger. Otherwise a {@link TLVException} is thrown.
 */
public class SequentialBERTLV {

	protected BERTLV[] mlstTlvs;
	protected short mTlvCount;

	/**
	 * Constructor creates an empty SequentialBERTLV object capable of encapsulating
	 * a SequentialBERTLV structure.
	 * <p/>
	 * The initial capacity is specified by the numTLVs argument.
	 * 
	 * @param numTLVs is the number of contained TLVs to allocate
	 * @throws TLVException with the following reason codes:
	 *                      <ul>
	 *                      <li>TLVException.INVALID_PARAM if numTLVs parameter is
	 *                      negative or larger than the maximum capacity supported
	 *                      by the implementation.</li>
	 *                      </ul>
	 */
	public SequentialBERTLV(short numTLVs) throws TLVException {
		resizeTLVArray(numTLVs);
		mTlvCount = 0;
	}

	/**
	 * Creates the SequentialBERTLV using the input binary data.
	 * <p/>
	 * Note: If bOff+bLen is greater than bArray.length, the length of the bArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param bArray input byte array
	 * @param bOff   offset within byte array containing the tlv data
	 * @param bLen   byte length of input data
	 * @return SequentialBERTLV
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
	public static SequentialBERTLV getInstance(byte[] bArray, short bOff, short bLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (bOff + bLen > bArray.length)
			JCEnvironmentExceptions.throwArrayIndexOutOfBoundsException();

		SequentialBERTLV tlv = new SequentialBERTLV((short) 0);
		tlv.init(bArray, bOff, bLen);
		return tlv;
	}

	/**
	 * Resizes data array.
	 * 
	 * @param numTLVs is the number of contained TLVs to allocate
	 * @return true if capacity is sufficient, false otherwise
	 */
	private boolean resizeTLVArray(short numTLVs) {

		if (mlstTlvs == null) {
			mlstTlvs = new BERTLV[numTLVs];
			return true;
		} else if (BERTLV.SUPPORT_EXPANSION) {
			if (mlstTlvs.length < numTLVs) {
				BERTLV[] newArray = new BERTLV[numTLVs];
				for (short idx = 0; idx < mlstTlvs.length; idx++)
					newArray[idx] = mlstTlvs[idx];
				mlstTlvs = newArray;
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * (Re-)Initializes this SequentialBERTLV object with the input tag and
	 * specified data as value of the object. Note that a reference to the BER Tag
	 * object is retained by this object. If the input BER Tag object is modified,
	 * the TLV structure encapsulated by this TLV instance is also modified.
	 * <p/>
	 * Each contained BERTLV is constructed and initialized using this init method.
	 * The initial capacity of each of the contained SequentialBERTLV objects is set
	 * to the number of TLVs contained at the top level of that TLV structure in the
	 * byte array.
	 * <p/>
	 * Note: If vOff+vLen is greater than vArray.length, the length of the vArray
	 * array, an ArrayIndexOutOfBoundsException exception is thrown.
	 * 
	 * @param tag    a BERTag object
	 * @param vArray the byte array containing vLen bytes of TLV Value
	 * @param vOff   offset within the vArray byte array where data begins
	 * @param vLen   byte length of the value data in vArray
	 * @return the resulting size of this TLV if represented in bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the input array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset or
	 *                                        array length parameter is negative
	 * @throws NullPointerException           if either tag or vArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.INSUFFICIENT_STORAGE
	 *                                        or if the required capacity is not
	 *                                        available and the implementation does
	 *                                        not support automatic expansion.</li>
	 *                                        </ul>
	 */
	public short init(byte[] vArray, short vOff, short vLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (vArray == null)
			JCEnvironmentExceptions.throwNullPointerException();

		short bOffset = vOff, bRemainingLength = vLen;

		while (bOffset < vArray.length && bRemainingLength > 0) {
			if ((vArray[bOffset] & BERTag.MASK_TAG_NUMBER) == BERTag.ASN1_EOC) {
				// Skip EOC character
				bOffset++;
				bRemainingLength--;
			} else {
				BERTLV tlv = BERTLV.getInstance(vArray, (short) bOffset, bRemainingLength);
				append(tlv);
				bOffset += tlv.size();
				bRemainingLength -= tlv.size();
			}
		}

		return getDataLength();
	}

	/**
	 * Append the specified TLV to the end of SequentialBERTLV. Note that a
	 * reference to the BER TLV object parameter is retained by this object. A
	 * change in the BER TLV object contents affects this TLV instance.
	 * 
	 * @param aTLV a BER TLV object
	 * @return the resulting size of this TLV if represented in bytes
	 * @throws NullPointerException if aTLV is null
	 * @throws TLVException         with the following reason codes:
	 *                              <ul>
	 *                              <li>TLVException.INSUFFICIENT_STORAGE if the
	 *                              required capacity is not available and the
	 *                              implementation does not support automatic
	 *                              expansion.</li>
	 *                              <li>TLVException.INVALID_PARAM if aTLV is this
	 *                              or this TLV object is contained in any of the
	 *                              constructed TLV objects in the hierarchy of the
	 *                              aTLV object.</li>
	 *                              </ul>
	 */
	public short append(BERTLV aTLV) throws NullPointerException, TLVException {
		if (!resizeTLVArray((short) (mTlvCount + 1)))
			TLVException.throwIt(TLVException.INSUFFICIENT_STORAGE);

		mlstTlvs[mTlvCount++] = aTLV;
		return getDataLength();
	}

	/**
	 * Delete the specified occurrence of the specified BER TLV from this
	 * SequentialBERTLV. The internal reference at the specified occurrence to the
	 * specified BER TLV object is removed.
	 * 
	 * @param aTLV          the BER TLV object to delete from this
	 * @param occurrenceNum specifies which occurrence of aTLV within this BER TLV
	 *                      to use
	 * @return the resulting size of this TLV if represented in bytes
	 * @throws NullPointerException if aTLV is null
	 * @throws TLVException         with the following reason codes:
	 *                              <ul>
	 *                              <li>TLVException.INVALID_PARAM if the specified
	 *                              BER TLV object parameter is not an element of
	 *                              this or occurs less than occurrenceNum times in
	 *                              this or occurrenceNum is 0 or negative.</li>
	 *                              </ul>
	 */
	public short delete(BERTLV aTLV, short occurrenceNum) throws NullPointerException, TLVException {

		short occurenceCounter = 0;
		short idxToRemove = -1;

		for (short idx = 0; idx < mTlvCount && idxToRemove == -1; idx++) {
			if (mlstTlvs[idx].getTag().equals(aTLV.getTag())) {
				if (++occurenceCounter == occurrenceNum)
					idxToRemove = idx;
			}
		}

		if (occurrenceNum <= 0 || occurrenceNum > occurenceCounter || occurenceCounter == 0)
			TLVException.throwIt(TLVException.INVALID_PARAM);

		if (idxToRemove != -1) {
			for (short idx = idxToRemove; idx < mTlvCount - 1; idx++) {
				mlstTlvs[idx] = mlstTlvs[idx + 1];
			}
			for (short idx = mTlvCount; idx < mlstTlvs.length; idx++) {
				mlstTlvs[idx] = null;
			}
			mTlvCount--;
		}

		return getDataLength();
	}

	/**
	 * Find the contained BERTLV within this SequentialBERTLV object that matches
	 * the specified BER Tag.
	 * <p/>
	 * If the tag parameter is null, the first contained BER TLV object is returned.
	 * 
	 * @param tag the BERTag to be found
	 * @return TLV object matching the indicated tag or null if none found.
	 */
	public BERTLV find(BERTag tag) {
		for (short idx = 0; idx < mTlvCount; idx++) {
			try {
				if (tag == null || mlstTlvs[idx].getTag().equals(tag)) {
					return mlstTlvs[idx];
				}
			} catch (TLVException e) {
				// Continue
			}
		}
		return null;
	}

	/**
	 * Find the next contained BERTLV within this SequentialBERTLV object that
	 * matches the specified BER Tag. The search must be started from the TLV
	 * position following the specified occurrence of the specified BER TLV object
	 * parameter.
	 * <p/>
	 * If the tag parameter is null, the next contained BER TLV object is returned.
	 * 
	 * @param tag           the BERTag to be found
	 * @param aTLV          tlv object contained within this BER TLV following which
	 *                      the search begins
	 * @param occurrenceNum specifies which occurrence of aTLV within this BER TLV
	 *                      to use
	 * @return TLV object matching the indicated tag or null if none found.
	 * @throws NullPointerException if aTLV is null
	 * @throws TLVException         with the following reason codes:
	 *                              <ul>
	 *                              <li>TLVException.INVALID_PARAM if the specified
	 *                              BER TLV object parameter is not an element of
	 *                              this or occurs less than occurrenceNum times in
	 *                              this or if occurrenceNum is 0 or negative.</li>
	 *                              </ul>
	 */
	public BERTLV findNext(BERTag tag, BERTLV aTLV, short occurrenceNum) throws NullPointerException, TLVException {

		short occurenceCounter = 0;
		short idxToStartFinding = -1;

		for (short idx = 0; idx < mTlvCount && idxToStartFinding == -1; idx++) {
			if (mlstTlvs[idx] == aTLV) {
				idxToStartFinding = (short) (idx + 1);
			}
		}

		if (occurrenceNum <= 0 || idxToStartFinding == -1)
			TLVException.throwIt(TLVException.INVALID_PARAM);

		for (short idx = idxToStartFinding; idx < mTlvCount; idx++) {
			if (tag == null || mlstTlvs[idx].getTag().equals(tag)) {
				if (++occurenceCounter == occurrenceNum)
					return mlstTlvs[idx];
			}
		}

		if (occurrenceNum > occurenceCounter || occurenceCounter == 0)
			TLVException.throwIt(TLVException.INVALID_PARAM);

		return null;
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
	protected short writeData(byte[] outArray, short bOff) {
		if (mlstTlvs == null)
			return 0;

		for (short idx = 0; idx < mTlvCount; idx++) {
			try {
				bOff += mlstTlvs[idx].toBytes(outArray, bOff);
			} catch (ArrayIndexOutOfBoundsException | NullPointerException | TLVException e) {
				// Should not happen
			}
		}
		return bOff;
	}

	/**
	 * [IMPLEMENTATION-SPECIFIC]
	 * <p/>
	 * Gets data length.
	 * 
	 * @return Data length.
	 */
	protected short getDataLength() {
		if (mlstTlvs == null)
			return 0;

		short dataLen;
		dataLen = 0;
		for (short idx = 0; idx < mTlvCount; idx++)
			try {
				dataLen += mlstTlvs[idx].size();
			} catch (TLVException e) {
				// Ignore empty or larger than 32767 (signed short)
			}
		return dataLen;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(String.format("Sequential TLV (Items = %d)\n", mTlvCount));
		sb.append(getDescription((short) 0));
		return sb.toString();
	}

	/**
	 * [IMPLEMENTATION-SPECIFIC] Gets number of stored TLVs.
	 * 
	 * @return Number of stored TLVs.
	 */
	public short getItemCount() {
		return mTlvCount;
	}

	/**
	 * [IMPLEMENTATION-SPECIFIC]
	 * <p/>
	 * Gets description of contents for {@link BERTLV}.
	 * 
	 * @param level Level of construction.
	 * @return String description of contents.
	 */
	public String getDescription(short level) {
		StringBuilder sb = new StringBuilder();
		for (short idx = 0; idx < mTlvCount; idx++) {
			BERTLV subTag = mlstTlvs[idx];
			sb.append(subTag.getDescription((short) level));
		}
		return sb.toString();
	}
}
