package com.jaloonz.tlv.utils;

import javacardx.framework.tlv.TLVException;

public class JCEnvironmentExceptions {

	private static final ArrayIndexOutOfBoundsException ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION = new ArrayIndexOutOfBoundsException();
	private static final NullPointerException NULL_POINTER_EXCEPTION = new NullPointerException();
	private static final TLVException TLV_EXCEPTION = new TLVException((short) 0);

	/**
	 * Throws {@link ArrayIndexOutOfBoundsException}.
	 * 
	 * @throws ArrayIndexOutOfBoundsException always
	 */
	public static void throwArrayIndexOutOfBoundsException() throws ArrayIndexOutOfBoundsException {
		throw ARRAY_INDEX_OUT_OF_BOUNDS_EXCEPTION;
	}

	/**
	 * Throws {@link NullPointerException}.
	 * 
	 * @throws NullPointerException always
	 */
	public static void throwNullPointerException() throws NullPointerException {
		throw NULL_POINTER_EXCEPTION;
	}

	/**
	 * Throws {@link TLVException}.
	 * 
	 * @param reason the reason for the exception
	 * @throws TLVException always
	 */
	public static void throwTLVException(short reason) throws TLVException {
		TLV_EXCEPTION.setReason(reason);
		throw TLV_EXCEPTION;
	}
}
