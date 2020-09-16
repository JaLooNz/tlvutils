package com.jaloonz.tlv.utils;

import javacardx.framework.Util;
import javacardx.framework.tlv.BERTag;
import javacardx.framework.tlv.ConstructedBERTLV;
import javacardx.framework.tlv.ConstructedBERTag;
import javacardx.framework.tlv.PrimitiveBERTLV;
import javacardx.framework.tlv.PrimitiveBERTag;
import javacardx.framework.tlv.TLVException;

public class TLVHelper {

	/**
	 * Gets the tag value.
	 * 
	 * @param tag Tag.
	 * @return Tag value.
	 */
	public static short getTag(BERTag tag) {

		try {
			byte[] tagBytes = new byte[4];
			short numBytes = tag.toBytes(tagBytes, (short) 0);
			short tagValue = 0;
			for (short idx = 0; idx < numBytes; idx++) {
				tagValue = (short) ((tagValue << 8) | (tagBytes[idx] & 0xFF));
			}
			return tagValue;
		} catch (ArrayIndexOutOfBoundsException | NullPointerException | TLVException e) {
			return 0;
		}
	}

	/**
	 * Writes the BER Tag bytes representing the specified tag value in the
	 * specified byte array
	 *
	 * @param tag      encodes the tag value.
	 * @param outArray output byte array
	 * @param bOff     offset within byte array containing first byte
	 * @return size of BER Tag output bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	public static short makeTag(short tag, byte[] outArray, short bOff) {

		if (outArray == null)
			throw new NullPointerException();

		makeTagBytes(tag, outArray, bOff);
		return getTagLength(tag);
	}

	/**
	 * Writes the BER Tag bytes representing the specified tag value in the
	 * specified byte array
	 *
	 * @param tag      encodes the tag value.
	 * @param outArray output byte array
	 * @param bOff     offset within byte array containing first byte
	 * @return size of BER Tag output bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	public static BERTag makeTag(short tag) {

		try {
			byte[] tagBytes = new byte[2];
			TLVHelper.makeTag(tag, tagBytes, (short) 0);
			return BERTag.getInstance(tagBytes, (short) 0);
		} catch (ArrayIndexOutOfBoundsException | NullPointerException | TLVException e) {
			return null;
		}
	}

	/**
	 * Writes the BER Tag bytes representing the specified tag value in the
	 * specified byte array
	 *
	 * @param tag      encodes the tag value.
	 * @param outArray output byte array
	 * @param bOff     offset within byte array containing first byte
	 * @return size of BER Tag output bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	private static void makeTagBytes(short tag, byte[] outArray, short bOff) {

		if (outArray == null)
			throw new NullPointerException();

		if ((tag & 0xFF00) != 0x0000) {
			outArray[bOff] = (byte) ((tag >> 8) & 0xFF);
			outArray[bOff + 1] = (byte) (tag & 0xFF);
			outArray[bOff + 2] = (byte) 0;
		} else {
			outArray[bOff] = (byte) (tag & 0xFF);
			outArray[bOff + 1] = (byte) 0;
		}
	}

	/**
	 * Writes the BER TLV bytes representing the specified tag value and data bytes
	 * in the specified byte array
	 *
	 * @param tag       encodes the tag value.
	 * @param inputData input data array
	 * @param outArray  output byte array
	 * @param bOff      offset within byte array containing first byte
	 * @return size of BER Tag output bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	public static short makeTLV(short tag, byte[] inputData, byte[] outArray, short bOff) {
		return makeTLV(tag, inputData, (short) 0, (short) inputData.length, outArray, bOff);
	}

	/**
	 * Writes the BER TLV bytes and returns it as a byte array
	 *
	 * @param tag       encodes the tag value.
	 * @param inputData input data array
	 * @return TLV byte array
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	public static byte[] makeTLV(short tag) {
		return makeTLV(tag, new byte[] {});
	}

	/**
	 * Writes the BER TLV bytes and returns it as a byte array
	 *
	 * @param tag       encodes the tag value.
	 * @param inputData input data array
	 * @return TLV byte array
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	public static byte[] makeTLV(short tag, byte[] inputData) {
		short dataLen = (short) inputData.length;
		short tlvLen = (short) (getTagLength(tag) + getLengthLength(dataLen) + dataLen);
		byte[] tlvData = new byte[tlvLen];
		makeTLV(tag, inputData, tlvData, (short) 0);
		return tlvData;
	}

	/**
	 * Concatenates the TLV arrays.
	 * 
	 * @param tlv1 TLV array 1.
	 * @param tlv2 TLV array 2.
	 * @return TLV array.
	 */
	public static byte[] concatTLV(byte[] tlv1, byte[] tlv2) {
		byte[] newArray = new byte[tlv1.length + tlv2.length];
		Util.arrayCopyNonAtomic(tlv1, (short) 0, newArray, (short) 0, (short) tlv1.length);
		Util.arrayCopyNonAtomic(tlv2, (short) 0, newArray, (short) tlv1.length, (short) tlv2.length);
		return newArray;
	}

	/**
	 * Writes the BER TLV bytes representing the specified tag value and data bytes
	 * in the specified byte array
	 *
	 * @param tag           encodes the tag value.
	 * @param inputData     input data array
	 * @param bInputDataOff input data start offset
	 * @param bInputDataLen input data length
	 * @param outArray      output byte array
	 * @param bOff          offset within byte array containing first byte
	 * @return size of BER Tag output bytes
	 * @throws ArrayIndexOutOfBoundsException if accessing the output array would
	 *                                        cause access of data outside array
	 *                                        bounds, or if the array offset
	 *                                        parameter is negative
	 * @throws NullPointerException           if outArray is null
	 */
	public static short makeTLV(short tag, byte[] inputData, short bInputDataOff, short bInputDataLen, byte[] outArray,
			short bOff) {

		if (outArray == null)
			throw new NullPointerException();

		try {
			makeTagBytes(tag, outArray, bOff);
			BERTag tagType = BERTag.getInstance(outArray, bOff);
			if (tagType.isConstructed()) {
				ConstructedBERTLV ctlv = new ConstructedBERTLV((short) 0);
				ctlv.init((ConstructedBERTag) tagType, inputData, bInputDataOff, bInputDataLen);
				return ctlv.toBytes(outArray, bOff);
			} else {
				PrimitiveBERTLV ptlv = new PrimitiveBERTLV((short) 0);
				ptlv.init((PrimitiveBERTag) tagType, inputData, bInputDataOff, bInputDataLen);
				return ptlv.toBytes(outArray, bOff);
			}
		} catch (ArrayIndexOutOfBoundsException | NullPointerException | TLVException e) {
			return 0;
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
	public static short getLengthLength(byte[] berTLVArray, short bOff) {
		if (berTLVArray[bOff] >= 0) // 0~7F
			return 1;
		else
			return (short) (1 + (berTLVArray[bOff] & 0x7F));
	}

	/**
	 * Gets the data length required to represent tag.
	 * 
	 * @param tag Tag value.
	 * @return Data length required to represent tag.
	 */
	public static short getTagLength(short tag) {
		if ((tag & 0xFF00) != 0x0000) {
			return 2;
		} else {
			return 1;
		}
	}

	/**
	 * Gets the data length required to represent value.
	 * 
	 * @param bLength Value length.
	 * @return Data length required to represent value.
	 */
	public static short getLengthLength(short bLength) {
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
}
