package com.jaloonz.tlv.utils;

public class LogHelper {

	/**
	 * Draws level structures for constructed TLVs.
	 * 
	 * @param level Level of construction.
	 * @return String representing level.
	 */
	public static String drawLevel(short level) {
	
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
