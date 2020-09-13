package TLVTest;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.commons.codec.binary.Hex;

import javacardx.framework.tlv.BERTLV;
import javacardx.framework.tlv.BERTag;
import javacardx.framework.tlv.PrimitiveBERTLV;
import javacardx.framework.tlv.TLVException;

import org.junit.Test;

public class TLVTester {

	@Test
	public void testBERTagParsing() {
		try {
			byte[] data1 = Hex.decodeHex(
					"610A4F08A000000151000000610E4F0CA000000151535041534B4D5361104F0EA0000001515350414C43434D414D61104D0EA0000001515350414C43434D444D610F4F0DA0000001515350415333535344610C4F0AA9A8A7A6A5A4A3A2A1A0610C4F0AA9A8A7A6A5A4A3A2A1A1610E4F0CA00000000353504200014201610E4F0CA00000015153504341534400610B4F09A00000015141434C0061124F10A0000000770107821D0000FE0000020061124F10A00000022053454353455350524F543161124F10A00000022053454353544F524147453161124F10A0000002201503010300000041524143610C4F0AA0A1A2A3A4A5A6A7A8A9610C4F0AA0A1A2A3A4A5A6A7A8AA61124F10A000000077020760110000FE0000FE00610B4F09A00000015143525300");
			BERTag tag1 = BERTag.getInstance(data1, (short) 0);
			assertNotNull("BER-Tag parsed", tag1);
			System.out.println(tag1.toString());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagParsingPrimitive() {
		try {
			byte[] data2 = Hex.decodeHex("810100");
			BERTag tag2 = BERTag.getInstance(data2, (short) 0);
			assertEquals(1, tag2.tagNumber());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagNumber1() {
		try {
			byte[] data2 = Hex.decodeHex("010100");
			BERTag tag2 = BERTag.getInstance(data2, (short) 0);
			assertEquals(1, tag2.tagNumber());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagNumber30() {
		try {
			byte[] data2 = Hex.decodeHex("1E0100");
			BERTag tag2 = BERTag.getInstance(data2, (short) 0);
			assertEquals(30, tag2.tagNumber());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagNumber31() {
		try {
			byte[] data2 = Hex.decodeHex("1F1F");
			BERTag tag2 = BERTag.getInstance(data2, (short) 0);
			assertEquals(31, tag2.tagNumber());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagNumber99() {
		try {
			byte[] data2 = Hex.decodeHex("BF630100");
			BERTag tag2 = BERTag.getInstance(data2, (short) 0);
			assertEquals(99, tag2.tagNumber());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagNumberMaxSignedShort() {
		try {
			byte[] data4 = Hex.decodeHex("BF81FF7F00");
			BERTag tag4 = BERTag.getInstance(data4, (short) 0);
			assertEquals(32767, tag4.tagNumber());
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagNumberMaxSignedShortExceeded() {
		try {
			byte[] data4 = Hex.decodeHex("BF82800000");
			BERTag tag4 = BERTag.getInstance(data4, (short) 0);
			assertEquals(32768, tag4.tagNumber());
			fail("Should hit exception");
		} catch (TLVException e) {
			// Correct
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagEqual() {
		try {
			byte[] data3 = Hex.decodeHex("BF630200");
			BERTag tag3 = BERTag.getInstance(data3, (short) 0);
			BERTag tag4 = BERTag.getInstance(data3, (short) 0);
			assertTrue("Compare should be equal for same object", tag4.equals(tag3));
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testBERTagReadAndWrite() {

		try {
			byte[] original = Hex.decodeHex("BF82FF7F0100");
			BERTag tag6 = BERTag.getInstance(original, (short) 0);

			byte[] rewrite = new byte[160];
			short outputLen = tag6.toBytes(rewrite, (short) 0);
			assertArrayEquals(Arrays.copyOf(original, outputLen), Arrays.copyOf(rewrite, outputLen));
		} catch (Exception | TLVException ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testWriteThreeTagBytes() {
		try {
			byte[] data7 = new byte[160];
			short tag7len = BERTag.toBytes(BERTag.BER_TAG_CLASS_MASK_APPLICATION, true, (short) 256, data7, (short) 0);

			byte[] expected = Hex.decodeHex("7F8200");
			assertArrayEquals(Arrays.copyOf(data7, tag7len), Arrays.copyOf(expected, tag7len));

			BERTag tag7 = BERTag.getInstance(data7, (short) 0);
			assertEquals(256, tag7.tagNumber());
		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testPrimitiveTLVAppend() {
		try {
			BERTLV tlv;
			byte[] data9 = Hex.decodeHex("C801000000000000000000");

			tlv = BERTLV.getInstance(data9, (short) 0, (short) data9.length);
			byte[] dataToAppend = new byte[] { 0x12, 0x34, 0x56, 0x78 };
			PrimitiveBERTLV.appendValue(data9, (short) 0, dataToAppend, (short) 0, (short) dataToAppend.length);

			byte[] expected = Hex.decodeHex("C8050012345678");
			assertArrayEquals(Arrays.copyOf(data9, expected.length), expected);

		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testPrimitiveTLVReplace() {
		try {
			byte[] data9 = Hex.decodeHex("C801000000000000000000");
			byte[] dataToAppend = new byte[] { 0x12, 0x34, 0x56, 0x78 };

			PrimitiveBERTLV tlv = (PrimitiveBERTLV) BERTLV.getInstance(data9, (short) 0, (short) data9.length);
			tlv.replaceValue(dataToAppend, (short) 0, (short) dataToAppend.length);
			tlv.toBytes(data9, (short) 0);

			byte[] expected = Hex.decodeHex("C80412345678");
			assertArrayEquals(Arrays.copyOf(data9, expected.length), expected);

		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testDecodingConstructedMultipleSequentialTLV() {
		try {
			byte[] data8 = Hex.decodeHex(
					"610A4F08A000000151000000610E4F0CA000000151535041534B4D5361104F0EA0000001515350414C43434D414D61104D0EA0000001515350414C43434D444D610F4F0DA0000001515350415333535344610C4F0AA9A8A7A6A5A4A3A2A1A0610C4F0AA9A8A7A6A5A4A3A2A1A1610E4F0CA00000000353504200014201610E4F0CA00000015153504341534400610B4F09A00000015141434C0061124F10A0000000770107821D0000FE0000020061124F10A00000022053454353455350524F543161124F10A00000022053454353544F524147453161124F10A0000002201503010300000041524143610C4F0AA0A1A2A3A4A5A6A7A8A9610C4F0AA0A1A2A3A4A5A6A7A8AA61124F10A000000077020760110000FE0000FE00610B4F09A00000015143525300");
			BERTLV tlv = BERTLV.getInstance(data8, (short) 0, (short) data8.length);
			System.out.println(tlv.toString());
		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}

	@Test
	public void testTLVDecodingPPSESelection() {
		try {
			byte[] data8 = Hex.decodeHex(
					"6F23840E325041592E5359532E4444463031A511BF0C0E610C4F07A0000000031010870101");
			BERTLV tlv = BERTLV.getInstance(data8, (short) 0, (short) data8.length);
			System.out.println(tlv.toString());
		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}


	@Test
	public void testTLVDecodingVisaSelection() {
		try {
			byte[] data8 = Hex.decodeHex(
					"6F348407A0000000031010A5299F381B9F66049F02069F03069F1A0295055F2A029A039C019F37049F4E14BF0C089F5A054007020702");
			BERTLV tlv = BERTLV.getInstance(data8, (short) 0, (short) data8.length);
			System.out.println(tlv.toString());
		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}
	
	@Test
	public void testTLVDecodingGPOResponse() {
		try {
			byte[] data8 = Hex.decodeHex(
					"7781E6820220409404180103009F360202059F260852D7F6595EFD1E2A9F10201F4A0132A00000000010030273000000004000000000000000000000000000009F4B81800CFF360C146FE6B1F0033753CBF984B71251881FA4218AD58B41E823D82C723FB31EE69CA5D4011E420B216B425AB16499C4F28E73B0C429C54975B67BCBA30E5458C5ADEA7578604C76343DDD18F62ED95B2160BB05EDD3A99465385DFD15F68E54B92C035D46D90B32F5D7EE8DB2834DA0827A21A69659A53469F8F783974C9F6C02008057131122334455667788D23072010000043299995F9F6E04238800009F270180");
			BERTLV tlv = BERTLV.getInstance(data8, (short) 0, (short) data8.length);
			System.out.println(tlv.toString());
		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}

	
	@Test
	public void testTLVDecodingReadRecord() {
		try {
			byte[] data8 = Hex.decodeHex(
					"70375F280207029F0702C0009F19060400100302735F3401009F241D5630303130303134363136323038343435323437383432393538323830");
			BERTLV tlv = BERTLV.getInstance(data8, (short) 0, (short) data8.length);
			System.out.println(tlv.toString());
		} catch (TLVException ex) {
			ex.printStackTrace();
		} catch (Exception ex) {
			fail("Other critical errors");
		}
	}
}
