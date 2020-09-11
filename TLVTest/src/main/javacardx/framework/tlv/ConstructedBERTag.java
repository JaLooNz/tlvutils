package javacardx.framework.tlv;

import javacardx.framework.Util;

/**
 * The ConstructedBERTag class encapsulates a constructed BER TLV tag. The rules on the allowed
 * encoding of the Tag field is based on the ASN.1 BER encoding rules of ISO/IEC 8825-1:2002.
 * <p>
 * The BERTag class and the subclasses ConstructedBERTag and PrimitiveBERTag, also provide static
 * methods to parse or edit a BER Tag structure representation in a byte array.
 */
public class ConstructedBERTag extends BERTag {
    /**
     * Constructor creates an empty constructed BERTLV Tag object capable of encapsulating a
     * constructed BER TLV Tag. All implementations must support at least 3 byte Tags which can
     * encode tag numbers up to 0x3FFF.
     */
    public ConstructedBERTag() {

    }

    @Override
    public void init(byte[] bArray, short bOff) throws ArrayIndexOutOfBoundsException, NullPointerException, TLVException {
        if (verifyFormat(bArray, bOff)) {
            if (!isConstructed(bArray, bOff))
                throw new TLVException(TLVException.MALFORMED_TAG);

            short tagLen = size(bArray, bOff);
            tagBytes = new byte[tagLen];
            Util.arrayCopyNonAtomic(bArray, (short) bOff, tagBytes, (short) 0, (short) tagLen);
        }
    }
}
