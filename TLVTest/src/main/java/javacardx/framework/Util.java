package javacardx.framework;

/**
 * The Util class contains common utility functions. Some of the methods may be implemented as
 * native functions for performance reasons. All methods in Util, class are static methods.
 * <p>
 * Some methods of Util, namely arrayCopy(), arrayCopyNonAtomic(), arrayFill(), arrayFillNonAtomic()
 * and setShort(), refer to the persistence of array objects. The term persistent means that arrays
 * and their values persist from one CAD session to the next, indefinitely. The JCSystem class is
 * used to control the persistence and transience of objects.
 */
public class Util {
    /**
     * Compares an array from the specified source array, beginning at the specified position, with
     * the specified position of the destination array from left to right. Returns the ternary result
     * of the comparison : less than(-1), equal(0) or greater than(1).
     * <p>
     * Note:
     * <p>
     * If srcOff or destOff or length parameter is negative an ArrayIndexOutOfBoundsException exception is thrown.
     * If srcOff+length is greater than src.length, the length of the src array a ArrayIndexOutOfBoundsException exception is thrown.
     * If destOff+length is greater than dest.length, the length of the dest array an ArrayIndexOutOfBoundsException exception is thrown.
     * If src or dest parameter is null a NullPointerException exception is thrown.
     *
     * @param src     source byte array
     * @param srcOff  offset within source byte array to start compare
     * @param dest    destination byte array
     * @param destOff offset within destination byte array to start compare
     * @param length  byte length to be compared
     * @return
     * @throws ArrayIndexOutOfBoundsException
     * @throws NullPointerException
     */
    public static final short arrayCompare(byte[] src,
                                           short srcOff,
                                           byte[] dest,
                                           short destOff,
                                           short length)
            throws ArrayIndexOutOfBoundsException,
            NullPointerException {

        if (srcOff < 0 || destOff < 0 || length < 0)
            throw new ArrayIndexOutOfBoundsException();

        if (src == null || dest == null)
            throw new NullPointerException();

        if (srcOff + length > src.length)
            throw new ArrayIndexOutOfBoundsException(src.length);

        if (destOff + length > dest.length)
            throw new ArrayIndexOutOfBoundsException(dest.length);

        for (short offset = 0; offset < length; offset++)
            if (src[srcOff + offset] < dest[destOff + offset])
                return -1;
            else if (src[srcOff + offset] > dest[destOff + offset])
                return 1;
        return 0;
    }

    /**
     * Copies an array from the specified source array, beginning at the specified position, to the
     * specified position of the destination array.
     *
     * @param src     source byte array
     * @param srcOff  offset within source byte array to start copy from
     * @param dest    destination byte array
     * @param destOff offset within destination byte array to start copy into
     * @param length  byte length to be copied
     * @return destOff+length
     * @throws ArrayIndexOutOfBoundsException if copying would cause access of data outside array bounds
     * @throws NullPointerException           if either src or dest is null
     */
    public static final short arrayCopy(byte[] src,
                                        short srcOff,
                                        byte[] dest,
                                        short destOff,
                                        short length)
            throws ArrayIndexOutOfBoundsException,
            NullPointerException {
        return arrayCopyNonAtomic(src, srcOff, dest, destOff, length);
    }

    /**
     * Copies an array from the specified source array, beginning at the specified position, to the
     * specified position of the destination array.
     *
     * @param src     source byte array
     * @param srcOff  offset within source byte array to start copy from
     * @param dest    destination byte array
     * @param destOff offset within destination byte array to start copy into
     * @param length  byte length to be copied
     * @return destOff+length
     * @throws ArrayIndexOutOfBoundsException if copying would cause access of data outside array bounds
     * @throws NullPointerException           if either src or dest is null
     */
    public static final short arrayCopyNonAtomic(byte[] src,
                                                 short srcOff,
                                                 byte[] dest,
                                                 short destOff,
                                                 short length)
            throws ArrayIndexOutOfBoundsException,
            NullPointerException {
        if (srcOff < 0 || destOff < 0 || length < 0)
            throw new ArrayIndexOutOfBoundsException();

        if (src == null || dest == null)
            throw new NullPointerException();

        if (srcOff + length > src.length)
            throw new ArrayIndexOutOfBoundsException(src.length);

        if (destOff + length > dest.length)
            throw new ArrayIndexOutOfBoundsException(dest.length);

        for (short offset = 0; offset < length; offset++)
            dest[destOff + offset] = src[srcOff + offset];

        return length;
    }

    /**
     * Concatenates the two parameter bytes to form a short value.
     *
     * @param b1 the first byte ( high order byte )
     * @param b2 the second byte ( low order byte )
     * @return the short value the concatenated result
     */
    public static final short makeShort(byte b1,
                                        byte b2) {
        return (short) (((b1 & 0xFF) << 8) | (b2 & 0xFF));
    }

    /**
     * Concatenates two bytes in a byte array to form a short value.
     *
     * @param bArray byte array
     * @param bOff   offset within byte array containing first byte (the high order byte)
     * @return the short value the concatenated result
     * @throws NullPointerException           if the bArray parameter is null
     * @throws ArrayIndexOutOfBoundsException if the bOff parameter is negative or if bOff+2 is
     *                                        greater than the length of bArray
     */
    public static final short getShort(byte[] bArray,
                                       short bOff)
            throws NullPointerException,
            ArrayIndexOutOfBoundsException {

        if (bArray == null)
            throw new NullPointerException();

        if (bOff < 0 || bOff + 2 > bArray.length)
            throw new ArrayIndexOutOfBoundsException();

        return makeShort(bArray[bOff], bArray[bOff + 1]);
    }

    /**
     * Deposits the short value as two successive bytes at the specified offset in the byte array.
     *
     * @param bArray byte array
     * @param bOff   offset within byte array containing first byte (the high order byte)
     * @param sValue the short value to set into array
     * @return bOff+2
     * @throws NullPointerException           if the bArray parameter is null
     * @throws ArrayIndexOutOfBoundsException if the bOff parameter is negative or if bOff+2 is
     *                                        greater than the length of bArray
     */
    public static final short setShort(byte[] bArray,
                                       short bOff,
                                       short sValue)
            throws TransactionException,
            NullPointerException,
            ArrayIndexOutOfBoundsException {

        if (bArray == null)
            throw new NullPointerException();

        if (bOff < 0 || bOff + 2 > bArray.length)
            throw new ArrayIndexOutOfBoundsException();

        bArray[bOff] = (byte) ((sValue >>> 8) & 0xFF);
        bArray[bOff + 1] = (byte) ((sValue) & 0xFF);

        return (short) (bOff + 2);
    }
}
