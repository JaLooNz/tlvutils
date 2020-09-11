package javacardx.framework.tlv;

import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

/**
 * The ConstructedBERTLV class encapsulates a constructed BER TLV structure. It
 * extends the generic BER TLV class. The rules on the allowed encoding of the
 * Tag, length and value fields is based on the ASN.1 BER encoding rules ISO/IEC
 * 8825-1:2002.
 * <p/>
 * The ConstructedBERTLV class only supports encoding of the length(L) octets in
 * definite form. The value(V) field which encodes the contents octets are
 * merely viewed as a set of other BERTLVs.
 * <p/>
 * Every ConstructedBERTLV has a capacity which represents the size of the
 * allocated internal data structures to reference all the contained BER TLV
 * objects. As long as the number of contained BER TLV objects of the
 * ConstructedBERTLV does not exceed the capacity, it is not necessary to
 * allocate new internal data. If the internal buffer overflows, and the
 * implementation supports automatic expansion which might require new data
 * allocation and possibly old data/object deletion, it is automatically made
 * larger. Otherwise a TLVException is thrown.
 * <p/>
 * The BERTLV class and the subclasses ConstructedBERTLV and PrimitiveBERTLV,
 * also provide static methods to parse or edit a TLV structure representation
 * in a byte array.
 */
public class ConstructedBERTLV extends BERTLV {

	protected BERTLV[] mlstTlvs;
	protected short mTlvCount;

	/**
	 * Constructor creates an empty ConstructedBERTLV object capable of
	 * encapsulating a ConstructedBERTLV structure.
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
	public ConstructedBERTLV(short numTLVs) throws TLVException {
		resizeConstructedTLVArray(numTLVs);
		mTlvCount = 0;
	}

	/**
	 * Resizes data array.
	 * 
	 * @param numTLVs is the number of contained TLVs to allocate
	 * @return true if capacity is sufficient, false otherwise
	 */
	private boolean resizeConstructedTLVArray(short numTLVs) {

		if (mlstTlvs == null) {
			mlstTlvs = new BERTLV[numTLVs];
			return true;
		} else if (SUPPORT_EXPANSION) {
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

	@Override
	public short init(byte[] bArray, short bOff, short bLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (bArray == null)
			throw new NullPointerException();

		if (bOff + bLen > bArray.length)
			throw new ArrayIndexOutOfBoundsException();

		short bOffset = bOff, bRemainingLength;
		short tagLen, lenLen, dataLen;

		mTag = BERTag.getInstance(bArray, bOffset);
		tagLen = mTag.size();
		lenLen = getLengthLength(bArray, (short) (bOffset + tagLen));
		dataLen = getLength(bArray, (short) (bOffset + tagLen));

		bOffset += tagLen + lenLen;
		bRemainingLength = dataLen;

		while (bOffset < bArray.length && bRemainingLength > 0) {
			if (bArray[bOffset] == ASN1_EOC) {
				// Skip EOC character
				bOffset++;
				bRemainingLength--;
			} else {
				System.out.println(Hex.encodeHex(Arrays.copyOfRange(bArray,  bOffset, bOffset+bRemainingLength),false));
				BERTLV tlv = BERTLV.getInstance(bArray, (short) bOffset, bRemainingLength);
				resizeConstructedTLVArray((short) (mTlvCount + 1));
				mlstTlvs[mTlvCount++] = tlv;
				bOffset += tlv.size();
				bRemainingLength -= tlv.size();
			}
		}

		//if (bRemainingLength != 0)
		//	throw new TLVException(TLVException.MALFORMED_TLV);

		calculateTLVSize();
		return mDataSize;
	}

	/**
	 * (Re-)Initializes this ConstructedBERTLV object with the input tag and TLV
	 * parameter. Note that a reference to the BER Tag object parameter is retained
	 * by this object. If the input BER Tag object is modified, the TLV structure
	 * encapsulated by this TLV instance is also modified. Similarly, a reference to
	 * the BER TLV object parameter is also retained by this object. If the input
	 * BER TLV object is modified, the TLV structure encapsulated by this TLV
	 * instance is also modified.
	 * 
	 * @param tag  a BERTag object
	 * @param aTLV to use to initialize as the value of this TLV
	 * @return the resulting size of this TLV if represented in bytes
	 * @throws NullPointerException if either tag or aTLV is null
	 * @throws TLVExceptionwith     the following reason codes:
	 *                              <ul>
	 *                              <li>TLVException.INSUFFICIENT_STORAGE if the
	 *                              required capacity is not available and the
	 *                              implementation does not support automatic
	 *                              expansion</li>
	 *                              <li>TLVException.INVALID_PARAM if aTLV is this
	 *                              or this TLV object is contained in any of the
	 *                              constructed TLV objects in the hierarchy of the
	 *                              aTLV object.</li>
	 *                              </ul>
	 */
	public short init(ConstructedBERTag tag, BERTLV aTLV) throws NullPointerException, TLVException {

		if (tag == null || aTLV == null)
			throw new NullPointerException();

		mTag = tag;

		return append(aTLV);
	}

	/**
	 * (Re-)Initializes this ConstructedBERTLV object with the input tag and
	 * specified data as value of the object. Note that a reference to the BER Tag
	 * object is retained by this object. If the input BER Tag object is modified,
	 * the TLV structure encapsulated by this TLV instance is also modified.
	 * <p/>
	 * Each contained BERTLV is constructed and initialized using this init method.
	 * The initial capacity of each of the contained ConstructedBERTLV objects is
	 * set to the number of TLVs contained at the top level of that TLV structure in
	 * the byte array.
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
	public short init(ConstructedBERTag tag, byte[] vArray, short vOff, short vLen)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (tag == null || vArray == null)
			throw new NullPointerException();

		mTag = tag;

		BERTLV tlv = BERTLV.getInstance(vArray, vOff, vLen);
		return append(tlv);
	}

	/**
	 * Append the specified TLV to the end of ConstructedBERTLV. Note that a
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
		mlstTlvs[mTlvCount++] = aTLV;
		calculateTLVSize();
		return mDataSize;
	}

	/**
	 * Delete the specified occurrence of the specified BER TLV from this
	 * ConstructedBERTLV. The internal reference at the specified occurrence to the
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

		for (short idx = 0; idx < mTlvCount && idxToRemove != -1; idx++) {
			if (mlstTlvs[idx].getTag().equals(aTLV.getTag())) {
				if (++occurenceCounter == occurrenceNum)
					idxToRemove = idx;
			}
		}

		if (occurrenceNum <= 0 || occurrenceNum > occurenceCounter || occurenceCounter == 0)
			throw new TLVException(TLVException.INVALID_PARAM);

		if (idxToRemove != -1) {
			for (short idx = idxToRemove; idx < mTlvCount; idx++) {
				mlstTlvs[idx] = mlstTlvs[idx + 1];
			}
			mTlvCount--;
		}

		calculateTLVSize();
		return mDataSize;
	}

	/**
	 * Find the contained BERTLV within this ConstructedBERTLV object that matches
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
				if (mlstTlvs[idx].getTag().equals(tag) || tag == null) {
					return mlstTlvs[idx];
				}
			} catch (TLVException e) {
				// Continue
			}
		}
		return null;
	}

	/**
	 * Find the next contained BERTLV within this ConstructedBERTLV object that
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

		for (short idx = 0; idx < mTlvCount && idxToStartFinding != -1; idx++) {
			if (mlstTlvs[idx] == aTLV) {
				idxToStartFinding = idx;
			}
		}

		if (occurrenceNum <= 0 || idxToStartFinding == -1)
			throw new TLVException(TLVException.INVALID_PARAM);

		for (short idx = idxToStartFinding; idx < mTlvCount; idx++) {
			if (mlstTlvs[idx].getTag().equals(tag) || tag == null) {
				if (++occurenceCounter == occurrenceNum)
					return mlstTlvs[idx];
			}
		}

		if (occurrenceNum > occurenceCounter || occurenceCounter == 0)
			throw new TLVException(TLVException.INVALID_PARAM);

		return null;
	}

	/**
	 * Append the TLV representation in the specified byte array to the constructed
	 * BER tlv representation in the specified output byte array.
	 * 
	 * @param berTLVInArray  input byte array
	 * @param bTLVInOff      offset within byte array containing the tlv data
	 * @param berTLVOutArray output TLV byte array
	 * @param bTLVOutOff     offset within byte array where output begins
	 * @return the size of the resulting output TLV
	 * @throws ArrayIndexOutOfBoundsException if accessing the input or output array
	 *                                        would cause access of data outside
	 *                                        array bounds, or if either array
	 *                                        offset parameter is negative
	 * @throws NullPointerException           if either berTLVInArray or
	 *                                        berTLVOutArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        TLV representation in the input byte
	 *                                        array is not a well-formed constructed
	 *                                        BER TLV.</li>
	 *                                        </ul>
	 */
	public static short append(byte[] berTLVInArray, short bTLVInOff, byte[] berTLVOutArray, short bTLVOutOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		BERTLV tlvToAppend = BERTLV.getInstance(berTLVInArray, bTLVInOff, (short) berTLVInArray.length);
		ConstructedBERTLV tlvConstructed = (ConstructedBERTLV) BERTLV.getInstance(berTLVOutArray, bTLVOutOff,
				(short) berTLVOutArray.length);
		tlvConstructed.append(tlvToAppend);
		return tlvConstructed.toBytes(berTLVOutArray, bTLVOutOff);
	}

	/**
	 * Find the offset of the contained TLV representation at the top level within
	 * the TLV structure representation in the specified byte array that matches the
	 * specified tag representation in the specified byte array
	 * <p/>
	 * If the tag array parameter is null, the offset of the first contained TLV is
	 * returned.
	 * 
	 * @param berTLVInArray input byte array
	 * @param bTLVInOff     offset within byte array containing the tlv data
	 * @param berTagArray   byte array containing the Tag to be searched
	 * @param bTagOff       offset within berTagArray byte array where tag data
	 *                      begins
	 * @return offset into berTLVArray where the indicated tag was found or -1 if
	 *         none found.
	 * @throws ArrayIndexOutOfBoundsException if accessing the input or output array
	 *                                        would cause access of data outside
	 *                                        array bounds, or if either array
	 *                                        offset parameter is negative
	 * @throws NullPointerException           if berTLVArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        TLV representation in the input byte
	 *                                        array is not a well-formed constructed
	 *                                        BER TLV.</li>
	 *                                        </ul>
	 */
	public static short find(byte[] berTLVArray, short bTLVOff, byte[] berTagArray, short bTagOff)
			throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		return findNext(berTLVArray, bTLVOff, (short) 0, berTagArray, bTagOff);
	}

	/**
	 * Find the offset of the next contained TLV representation at the top level
	 * within the TLV structure representation in the specified byte array that
	 * matches the specified tag representation in the specified byte array.
	 * <p/>
	 * The search must be started from the TLV position following the specified
	 * startOffset parameter where a contained TLV exists at the top level.
	 * <p/>
	 * If the tag array parameter - berTagArray - is null, the offset of the next
	 * contained TLV representation at the top level is returned.
	 * 
	 * @param berTLVArray input byte array
	 * @param bTLVOff     offset within byte array containing the TLV data
	 * @param startOffset offset within the input berTLVArray to begin the search
	 * @param berTagArray byte array containing the Tag to be searched
	 * @param bTagOff     offset within berTagArray byte array where tag data begins
	 * @return offset into berTLVArray where the indicated tag was found or -1 if
	 *         none found.
	 * @throws ArrayIndexOutOfBoundsException if accessing the input arrays would
	 *                                        cause access of data outside array
	 *                                        bounds, or if any of the array offset
	 *                                        parameters is negative
	 * @throws NullPointerException           if berTLVArray is null
	 * @throws TLVException                   with the following reason codes:
	 *                                        <ul>
	 *                                        <li>TLVException.MALFORMED_TLV if the
	 *                                        TLV representation in the specified
	 *                                        byte array is not a well-formed
	 *                                        constructed BER TLV structure.</li>
	 *                                        <li>TLVException.MALFORMED_TAG if the
	 *                                        tag representation in the specified
	 *                                        byte array is not a well-formed BER
	 *                                        Tag structure.</li>
	 *                                        <li>TLVException.INVALID_PARAM if the
	 *                                        berTLVArray array does not contain a
	 *                                        top level contained TLV element at the
	 *                                        specified startOffset offset.</li>
	 *                                        </ul>
	 */
	public static short findNext(byte[] berTLVArray, short bTLVOff, short startOffset, byte[] berTagArray,
			short bTagOff) throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {

		if (berTLVArray == null)
			throw new NullPointerException();

		short bOffset = (short) (bTLVOff + startOffset), bRemainingLength = (short) (berTLVArray.length - bTLVOff);
		BERTag tagToFind = BERTag.getInstance(berTagArray, bTagOff);
		while (bOffset < berTLVArray.length && bRemainingLength > 0) {
			if (berTLVArray[bOffset++] == ASN1_EOC) {
				// Skip EOC character
				bOffset++;
				bRemainingLength--;
			} else {
				BERTLV tlv = BERTLV.getInstance(berTLVArray, bOffset, bRemainingLength);
				if (tlv.getTag().equals(tagToFind) || berTagArray == null) {
					return bOffset;
				}
				bOffset += tlv.size();
				bRemainingLength -= tlv.size();
			}
		}
		// Not found
		return -1;
	}

	private short getDataSize() {
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

	private void calculateTLVSize() {
		try {
			short tagLen, lenLen, dataLen;
			tagLen = mTag.size();
			dataLen = getDataSize();
			lenLen = BERTLV.getLengthLength(dataLen);
			mDataSize = (short) (tagLen + lenLen + dataLen);
		} catch (TLVException ex) {
			mDataSize = 0;
		}
	}

	@Override
	public String getDescription(short level) {
		StringBuilder sb = new StringBuilder();
		sb.append(drawLevel(level));
		if (mTag != null) {
			sb.append(String.format("T=%s, L=%d (SubItems=%d)\n", mTag.toString(), mDataSize, mTlvCount));
			for (short idx = 0; idx < mTlvCount; idx++) {
				BERTLV subTag = mlstTlvs[idx];
				sb.append(subTag.getDescription((short) (level + 1)));
			}
		} else {
			sb.append("Invalid TLV\n");
		}
		return sb.toString();
	}
}
