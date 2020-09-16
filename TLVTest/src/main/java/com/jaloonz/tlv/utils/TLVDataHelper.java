package com.jaloonz.tlv.utils;

import java.util.Map;

import javacardx.framework.tlv.BERTLV;
import javacardx.framework.tlv.ConstructedBERTLV;
import javacardx.framework.tlv.PrimitiveBERTLV;
import javacardx.framework.tlv.TLVException;

/**
 * Utility to help format TLV data based on structural element definitions (in
 * TLV format with length 0).
 * <p/>
 */
public class TLVDataHelper {

	public static final byte[] EMPTY_ARRAY = new byte[0];

	/**
	 * Generates TLV structure with data from data map.
	 * 
	 * @param tlv            TLV structure.
	 * @param tlvArrays      TLV data array.
	 * @param bRemoveMissing Remove missing data tags.
	 *                       <p/>
	 *                       If true, tag will be removed entirely from structure if
	 *                       not present in TLV data array.
	 *                       <p/>
	 *                       If false, data not present in TLV data array will be
	 *                       set to 0 length.
	 * @return True if value present, false if values missing.
	 */
	private static boolean updateTLVStructureData(BERTLV tlv, Map<Short, byte[]> tlvArrays, boolean bRemoveMissing) {

		boolean bValuePresent = false;

		try {
			if (tlv.getTag().isConstructed()) {

				ConstructedBERTLV ctlv = (ConstructedBERTLV) tlv;
				BERTLV currTlv, lastTlv;

				currTlv = ctlv.find(null);
				lastTlv = null;
				while (currTlv != null) {
					boolean bTlvDeleted = false;
					if (!updateTLVStructureData(currTlv, tlvArrays, bRemoveMissing)) {
						if (bRemoveMissing) {
							// No sub-element in constructed tag, remove constructed tag
							ctlv.delete(currTlv, (short) 1);
							bTlvDeleted = true;
						}
					} else {
						bValuePresent = true;
					}

					if (!bTlvDeleted)
						lastTlv = currTlv;

					if (lastTlv == null)
						currTlv = ctlv.find(null);
					else
						currTlv = ctlv.findNext(null, lastTlv, (short) 1);
				}

			} else {

				PrimitiveBERTLV ptlv = (PrimitiveBERTLV) tlv;
				short tagValue = TLVHelper.getTag(ptlv.getTag());
				if (tlvArrays != null && tlvArrays.containsKey(tagValue)) {
					byte[] data = tlvArrays.get(tagValue);
					ptlv.replaceValue(data, (short) 0, (short) data.length);
					bValuePresent = true;
				} else {
					if (bRemoveMissing) {
						// Hints to delete inner TLV.
						bValuePresent = false;
					} else {
						ptlv.replaceValue(EMPTY_ARRAY, (short) 0, (short) EMPTY_ARRAY.length);
						bValuePresent = true;
					}
				}
			}
		} catch (TLVException e) {
			// Ignore TLVException
		}
		return bValuePresent;
	}

	/**
	 * Writes TLV structure with values from data map to byte array.
	 * 
	 * @param tlvStructure   TLV structure.
	 * @param tlvArrays      Data map with new values.
	 * @param bRemoveMissing Remove missing data tags.
	 *                       <p/>
	 *                       If true, tag will be removed entirely from structure if
	 *                       not present in TLV data array.
	 *                       <p/>
	 *                       If false, data not present in TLV data array will be
	 *                       set to 0 length.
	 * @return TLV structure with values.
	 */
	public static byte[] writeTLVWithValues(byte[] tlvStructure, Map<Short, byte[]> tlvArrays, boolean bRemoveMissing) {
		try {
			BERTLV tlv = BERTLV.getInstance(tlvStructure, (short) 0, (short) tlvStructure.length);
			updateTLVStructureData(tlv, tlvArrays, bRemoveMissing);
			short structureLen;
			structureLen = tlv.size();
			byte[] structure = new byte[structureLen];
			tlv.toBytes(structure, (short) 0);
			return structure;
		} catch (NullPointerException | TLVException e) {
			return null;
		}
	}

	/**
	 * Writes TLV structure to byte array.
	 * 
	 * @param tlv TLV structure.
	 * @return TLV structure, or null if invalid TLV.
	 */
	public static byte[] writeTLVStructure(BERTLV tlv) {
		try {
			updateTLVStructureData(tlv, null, false);
			short structureLen;
			structureLen = tlv.size();
			byte[] structure = new byte[structureLen];
			tlv.toBytes(structure, (short) 0);
			return structure;
		} catch (NullPointerException | TLVException e) {
			return null;
		}
	}
}
