/* 
**	AES standard / Rijndael proposal document:
**	https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
*/

import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

import java.lang.StringBuilder;
import java.lang.Byte;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;


class AES {
	// maps hex values to SBOX/INVSBOX indexes
	private static final Map<Character, Integer> hexMap = createMap();
	public static int BLOCK_LENGTH = 16; // 16 bytes -> 128 bits
	public static int KEY_LENGTH = 128; // in bits
	public static int STATE_ROWS = 4, STATE_COLS = 4;

	// Rijndael S-box
	public static final int[][] sbox = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
    
    /*
    private static String[][] SBOX = new String[][]{
		{ "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
		{ "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
		{ "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
		{ "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
		{ "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
		{ "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" }, 
		{ "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" }, 
		{ "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" }, 
		{ "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" }, 
		{ "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" }, 
		{ "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" }, 
		{ "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" }, 
		{ "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" }, 
		{ "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" }, 
		{ "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" }, 
		{ "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
    };
    */

    // Rijndael Inverted S-box
    public static final int[][] invsbox = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
    /*
    private static String[][] INVSBOX = new String[][]{
	    { "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
	    { "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" },
	    { "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" },
	    { "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" },
	    { "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" }, 
	    { "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" }, 
	    { "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" }, 
	    { "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" }, 
	    { "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" }, 
	    { "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" }, 
	    { "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" }, 
	    { "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" }, 
	    { "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" }, 
	    { "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" }, 
	    { "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" }, 
	    { "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" }
    };
	*/

	public static void main(String[] args) throws NoSuchAlgorithmException {
		// create new key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(KEY_LENGTH);
		SecretKey secretKey = keyGen.generateKey();
		// byte[] keyB = secretKey.getEncoded();

		String input = "helloworldwhenyougethere";//scanner.nextLine();
		int[] intArr = convertToIntArray(input.getBytes());
		printArray(intArr);

		int[] paddedInput = applyPadding(intArr);
		printArray(paddedInput);

		int[][] state = inputToState(Arrays.copyOfRange(paddedInput, 0, BLOCK_LENGTH));

		printState(state);

		subBytes(state);

		printState(state);

		shiftRows(state);

		printState(state);


	}

	/**
     * Applies padding to input to obtain input length equal to multiple of BLOCK_LENGTH
     * @param input Array to be padded
     * @return new array with padding applied
     */
    public static int[] applyPadding(int[] input) {
    	// Exces bytes 
    	int extraBytes = input.length % BLOCK_LENGTH;
		// Padding required for the input length to be a multiple of BLOCK_LENGTH
		int numPaddingBytes = BLOCK_LENGTH - extraBytes;

		// Final padded array
		int[] paddedInput = new int[input.length + numPaddingBytes];

		// Temporary array to hold padding - pad the last block with n bytes all with value n
   		int[] padding = new int[numPaddingBytes];   		
		Arrays.fill(padding, numPaddingBytes);

   		// Copy array contents to create final padded array
   		System.arraycopy(input, 0, paddedInput, 0, input.length);
   		System.arraycopy(padding, 0, paddedInput, input.length, padding.length);
    	
    	return paddedInput;
    }


    /**
     * Generate 4x4 2D state array from 1D input
     * @param input Array used to fill state
     * @return 2D state array filled in Column Major Order
     */
    private static int[][] inputToState(int[] input) {
   		int[][] state = new int[STATE_ROWS][STATE_COLS];
   		for(int row = 0; row < STATE_ROWS; row++){
   			for(int col = 0; col < STATE_COLS; col++){
   				state[row][col] = input[row + STATE_COLS*col];
   			}
   		}
   		return state;
    }

	/**
     * Replaces all elements in the passed array with values in sbox[][].
     * @param state Array whose value will be replaced
     */
	public static void subBytes(int[][] state) {
		for (int row = 0; row < STATE_ROWS; row++) {
			for (int col = 0; col < STATE_COLS; col++) {
				// hex val is used to determine row/col coords of sbox value
				int hex = state[row][col];
				state[row][col] = sbox[hex / 16][hex % 16];
			}
		}
	}

	/**
     * Shifts 2nd,3rd,4th rows of state by row index
     * @param state Array whose 2nd,3rd,4th rows will be shifted
     */
	public static void shiftRows(int[][] state) {
		for (int row = 0; row < STATE_ROWS; row++) {
			state[row] = rotateLeft(state[row], row);
		}
	}

	/** 
	 * Helper function - shifts an array's cells by 'offset' places to the left
     * @param arr array to be rotated
     * @param offset number of left rotations
     * @return rotated array
     */
	public static int[] rotateLeft(int[] arr, int offset) {
		// will yield same arr
		if (offset % 4 == 0) {
			return arr;
		}
		while (offset > 0) {
			int temp = arr[0];
			for (int i = 0; i < arr.length-1; i++) {
				arr[i] = arr[i+1];
			}
			arr[arr.length-1] = temp;
			offset--;
		}
		return arr;
	}

    

    // // State: two-dimensional array of bytes in Column Major Order
    // private static byte[][] inputToOriginalState(byte[] input) {
   	// 	byte[][] State = new byte[STATE_ROWS][STATE_COLS];
   	// 	for(int row = 0; row < STATE_ROWS; row++){
   	// 		for(int col = 0; col < STATE_COLS; col++){
   	// 			State[row][col] = input[row + STATE_COLS*col];
   	// 		}
   	// 	}
   	// 	return State;
    // }

    // private static String bytesToHex(byte[] hashInBytes) {
    //     StringBuilder sb = new StringBuilder();
    //     for (byte b : hashInBytes) {
    //         sb.append(String.format("%02x", b));
    //     }
    //     return sb.toString();
    // }

    public static byte hexToByte(String hexString) {
	    int firstDigit = Character.getNumericValue(hexString.charAt(0));
	    int secondDigit = Character.getNumericValue(hexString.charAt(1));
	    return (byte) ((firstDigit << 4) + secondDigit);
	}

    private static String[] byteArrToHexArr(byte[] bArr) {
        String[] s = new String[bArr.length];
        for(int i = 0; i < bArr.length; i++) {
            s[i] = String.format("%02x", bArr[i]);
        }
        return s;
    }

	public static String byteToHex(byte b) {
	    int i = b & 0xFF;
	    return Integer.toHexString(i);
  	}

  	public static int[] convertToIntArray(byte[] input) {
	    int[] ret = new int[input.length];
	    for (int i = 0; i < input.length; i++)
	    {
	        ret[i] = input[i]; // & 0xff; // Range 0 to 255, not -128 to 127
	    }
	    return ret;
	}

  	// maps hex values to SBOX/INVSBOX indexes
  	private static Map<Character, Integer> createMap() {
        Map<Character,Integer> map = new HashMap<Character,Integer>();
        map.put('0', 0);
        map.put('1', 1);
        map.put('2', 2);
        map.put('3', 3);
        map.put('4', 4);
        map.put('5', 5);
        map.put('6', 6);
        map.put('7', 7);
        map.put('8', 8);
        map.put('9', 9);
        map.put('a', 10);
        map.put('b', 11);
        map.put('c', 12);
        map.put('d', 13);
        map.put('e', 14);
        map.put('f', 15);
        return map;
    }

  	


	///////////////////////////////////////////////////////////////////
	//																 //
	//						FOR DEBUGGING							 //
	//																 //
	///////////////////////////////////////////////////////////////////		

	private static void printIntInBits(int n) {
		System.out.println(String.format("%08d", Integer.parseInt(Integer.toBinaryString(n))));
	}

	private static int getBit(byte b, int pos) {
     	int bitVal = b>>(8-(pos+1)) & 0x01;
     	return bitVal;
    }


    public static void printArrayInBits(byte[] b) {
    	System.out.println();
   		int counter = 0;
		for(int j = 0; j < b.length; j++){
			for(int i = 0; i < 8; i++){
				System.out.print(getBit(b[j], i));
				counter++;
			}
		}
		System.out.println();
		System.out.println(counter);
		System.out.println();
    }

    public static void printArray(int[] b) {
	    for(int i = 0; i < b.length; i++){
			System.out.print(b[i] + " ");
		}
		System.out.println();
	}


    public static void printState(int[][] state) {
  //   	State = inputToOriginalState(Arrays.copyOfRange(paddedInput, 16, paddedInput.length));
		// printState(State);

		for(int row = 0; row < 4; row++){
			System.out.println();
			for(int col = 0; col < 4; col++){
				System.out.print(state[row][col] + " ");
			}
		}
		System.out.println();
    }

    public static void getOrginalKey(String encodedKey) {
    	// decode the base64 encoded string
		byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
		// rebuild key using SecretKeySpec
		SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		System.out.println(originalKey);
    }

    public static String toStringKey(SecretKey secretKey) {
    	// get base64 encoded version of the key
		String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
		return encodedKey;
    }

}