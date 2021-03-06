/* 
**	AES standard / Rijndael proposal document:
**	https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
**
**  https://infosecwriters.com/text_resources/pdf/AESbyExample.pdf
*/

import java.util.Scanner;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Base64;

import java.lang.StringBuilder;
import java.lang.Byte;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.NoSuchAlgorithmException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;


class AES {
	// maps hex values to SBOX/INVSBOX indexes
	public static int BLOCK_LENGTH = 16; // 16 bytes -> 128 bits
	public static int DEFAULT_KEY_LENGTH = 128; // in bits
	public static int STATE_ROWS = 4, STATE_COLS = 4;

	/**
	 * Rijndael S-box
	 */
	public static final int[][] sbox = {{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76}, {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0}, {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15}, {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75}, {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84}, {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf}, {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8}, {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2}, {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73}, {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb}, {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79}, {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08}, {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a}, {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e}, {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf}, {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};

    /*
     * Rijndael Inverted S-box
     */
    public static final int[][] invsbox = {{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb}, {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb}, {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e}, {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25}, {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92}, {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84}, {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06}, {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b}, {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73}, {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e}, {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b}, {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4}, {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f}, {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef}, {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61}, {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};

    /**
     * Galois table used for mixColumns
     */
    public static final int[][] galois = {
    	{0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    /**
     * Inverse Galois table used for invMixColumns
     */
    public static final int[][] invgalois = {
    	{0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
    };

    /**
     * L table used for mixColumns
     */
	public static final int[][] LTable = {
		{ 0x00, 0x00, 0x19, 0x01, 0x32, 0x02, 0x1A, 0xC6, 0x4B, 0xC7, 0x1B, 0x68, 0x33, 0xEE, 0xDF, 0x03 },
		{ 0x64, 0x04, 0xE0, 0x0E, 0x34, 0x8D, 0x81, 0xEF, 0x4C, 0x71, 0x08, 0xC8, 0xF8, 0x69, 0x1C, 0xC1 },
		{ 0x7D, 0xC2, 0x1D, 0xB5, 0xF9, 0xB9, 0x27, 0x6A, 0x4D, 0xE4, 0xA6, 0x72, 0x9A, 0xC9, 0x09, 0x78 },
		{ 0x65, 0x2F, 0x8A, 0x05, 0x21, 0x0F, 0xE1, 0x24, 0x12, 0xF0, 0x82, 0x45, 0x35, 0x93, 0xDA, 0x8E },
		{ 0x96, 0x8F, 0xDB, 0xBD, 0x36, 0xD0, 0xCE, 0x94, 0x13, 0x5C, 0xD2, 0xF1, 0x40, 0x46, 0x83, 0x38 },
		{ 0x66, 0xDD, 0xFD, 0x30, 0xBF, 0x06, 0x8B, 0x62, 0xB3, 0x25, 0xE2, 0x98, 0x22, 0x88, 0x91, 0x10 },
		{ 0x7E, 0x6E, 0x48, 0xC3, 0xA3, 0xB6, 0x1E, 0x42, 0x3A, 0x6B, 0x28, 0x54, 0xFA, 0x85, 0x3D, 0xBA },
		{ 0x2B, 0x79, 0x0A, 0x15, 0x9B, 0x9F, 0x5E, 0xCA, 0x4E, 0xD4, 0xAC, 0xE5, 0xF3, 0x73, 0xA7, 0x57 },
		{ 0xAF, 0x58, 0xA8, 0x50, 0xF4, 0xEA, 0xD6, 0x74, 0x4F, 0xAE, 0xE9, 0xD5, 0xE7, 0xE6, 0xAD, 0xE8 },
		{ 0x2C, 0xD7, 0x75, 0x7A, 0xEB, 0x16, 0x0B, 0xF5, 0x59, 0xCB, 0x5F, 0xB0, 0x9C, 0xA9, 0x51, 0xA0 },
		{ 0x7F, 0x0C, 0xF6, 0x6F, 0x17, 0xC4, 0x49, 0xEC, 0xD8, 0x43, 0x1F, 0x2D, 0xA4, 0x76, 0x7B, 0xB7 },
		{ 0xCC, 0xBB, 0x3E, 0x5A, 0xFB, 0x60, 0xB1, 0x86, 0x3B, 0x52, 0xA1, 0x6C, 0xAA, 0x55, 0x29, 0x9D },
		{ 0x97, 0xB2, 0x87, 0x90, 0x61, 0xBE, 0xDC, 0xFC, 0xBC, 0x95, 0xCF, 0xCD, 0x37, 0x3F, 0x5B, 0xD1 },
		{ 0x53, 0x39, 0x84, 0x3C, 0x41, 0xA2, 0x6D, 0x47, 0x14, 0x2A, 0x9E, 0x5D, 0x56, 0xF2, 0xD3, 0xAB },
		{ 0x44, 0x11, 0x92, 0xD9, 0x23, 0x20, 0x2E, 0x89, 0xB4, 0x7C, 0xB8, 0x26, 0x77, 0x99, 0xE3, 0xA5 },
		{ 0x67, 0x4A, 0xED, 0xDE, 0xC5, 0x31, 0xFE, 0x18, 0x0D, 0x63, 0x8C, 0x80, 0xC0, 0xF7, 0x70, 0x07 }
	};

	/**
     * E table used for mixColumns
     */
	public static final int[][] ETable = {
		{ 0x01, 0x03, 0x05, 0x0F, 0x11, 0x33, 0x55, 0xFF, 0x1A, 0x2E, 0x72, 0x96, 0xA1, 0xF8, 0x13, 0x35 },
		{ 0x5F, 0xE1, 0x38, 0x48, 0xD8, 0x73, 0x95, 0xA4, 0xF7, 0x02, 0x06, 0x0A, 0x1E, 0x22, 0x66, 0xAA },
		{ 0xE5, 0x34, 0x5C, 0xE4, 0x37, 0x59, 0xEB, 0x26, 0x6A, 0xBE, 0xD9, 0x70, 0x90, 0xAB, 0xE6, 0x31 },
		{ 0x53, 0xF5, 0x04, 0x0C, 0x14, 0x3C, 0x44, 0xCC, 0x4F, 0xD1, 0x68, 0xB8, 0xD3, 0x6E, 0xB2, 0xCD },
		{ 0x4C, 0xD4, 0x67, 0xA9, 0xE0, 0x3B, 0x4D, 0xD7, 0x62, 0xA6, 0xF1, 0x08, 0x18, 0x28, 0x78, 0x88 },
		{ 0x83, 0x9E, 0xB9, 0xD0, 0x6B, 0xBD, 0xDC, 0x7F, 0x81, 0x98, 0xB3, 0xCE, 0x49, 0xDB, 0x76, 0x9A },
		{ 0xB5, 0xC4, 0x57, 0xF9, 0x10, 0x30, 0x50, 0xF0, 0x0B, 0x1D, 0x27, 0x69, 0xBB, 0xD6, 0x61, 0xA3 },
		{ 0xFE, 0x19, 0x2B, 0x7D, 0x87, 0x92, 0xAD, 0xEC, 0x2F, 0x71, 0x93, 0xAE, 0xE9, 0x20, 0x60, 0xA0 },
		{ 0xFB, 0x16, 0x3A, 0x4E, 0xD2, 0x6D, 0xB7, 0xC2, 0x5D, 0xE7, 0x32, 0x56, 0xFA, 0x15, 0x3F, 0x41 },
		{ 0xC3, 0x5E, 0xE2, 0x3D, 0x47, 0xC9, 0x40, 0xC0, 0x5B, 0xED, 0x2C, 0x74, 0x9C, 0xBF, 0xDA, 0x75 },
		{ 0x9F, 0xBA, 0xD5, 0x64, 0xAC, 0xEF, 0x2A, 0x7E, 0x82, 0x9D, 0xBC, 0xDF, 0x7A, 0x8E, 0x89, 0x80 },
		{ 0x9B, 0xB6, 0xC1, 0x58, 0xE8, 0x23, 0x65, 0xAF, 0xEA, 0x25, 0x6F, 0xB1, 0xC8, 0x43, 0xC5, 0x54 },
		{ 0xFC, 0x1F, 0x21, 0x63, 0xA5, 0xF4, 0x07, 0x09, 0x1B, 0x2D, 0x77, 0x99, 0xB0, 0xCB, 0x46, 0xCA },
		{ 0x45, 0xCF, 0x4A, 0xDE, 0x79, 0x8B, 0x86, 0x91, 0xA8, 0xE3, 0x3E, 0x42, 0xC6, 0x51, 0xF3, 0x0E },
		{ 0x12, 0x36, 0x5A, 0xEE, 0x29, 0x7B, 0x8D, 0x8C, 0x8F, 0x8A, 0x85, 0x94, 0xA7, 0xF2, 0x0D, 0x17 },
		{ 0x39, 0x4B, 0xDD, 0x7C, 0x84, 0x97, 0xA2, 0xFD, 0x1C, 0x24, 0x6C, 0xB4, 0xC7, 0x52, 0xF6, 0x01 }
	};

	public static final int[] rconTable = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a};


	public static void main(String[] args) throws NoSuchAlgorithmException {
		int keySize = 0;		
		if (args.length == 0) {
			keySize = DEFAULT_KEY_LENGTH;
		} else {
			try {
				keySize = Integer.parseInt(args[0]);
				if(keySize != 128 && keySize != 192 && keySize != 256) {
					throw new Exception("Invalid argument. Key size must be equal to 128, 192 or 256.");
				}
			} catch(Exception e) {
				System.out.println("Invalid argument. Key size must be equal to 128, 192 or 256.");
				System.out.println("Or leave arguments empty for default key size: 128");
				return;
			}
		}

		int numAESRounds = 0, numKeyExpRounds = 0;
		if (keySize == 128) {
			numAESRounds = 10;
			numKeyExpRounds = 44;
		} else if(keySize == 192) {
			numAESRounds = 12;
			numKeyExpRounds = 52;
		} else {
			numAESRounds = 14;
			numKeyExpRounds = 60;
		}

		// create new key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(keySize);
		SecretKey secretKey = keyGen.generateKey();

		int[] key = convertToIntArray(secretKey.getEncoded());

		int[] expandedKey = expandKey(key, numAESRounds, numKeyExpRounds); //16:44, 24:52, 32:60

		System.out.println("KEY " + Arrays.toString(key) + " -> " + key.length);
		// System.out.println("Expanded KEY " + Arrays.toString(expandedKey) + " -> " + expandedKey.length);

		// System.out.println();

		String input = "helloworldwhenyougethere";//scanner.nextLine();
		System.out.println("Input bytes: " + Arrays.toString(input.getBytes()));
		String cipher = encrypt(input, expandedKey, numAESRounds);
		System.out.println("Encrypted string: " + cipher);

		// int[] plaintextArr = decrypt(cipher, expandedKey, 10);
		// System.out.println("Output bytes: " + Arrays.toString(plaintextArr));
	}

	/**
     * Performs the encryption of input text
     * @param input plaintext to be encrypted
     * @return encrypted plaintext -> ciphertext
     */ 
	public static String encrypt(String input, int[] expandedKey, int numRounds) {
		System.out.println("Encrypting...");

		/* Input preprocessing to generate even an number of blocks when converting to state format */
		int[] paddedInput = applyPadding( convertToIntArray(input.getBytes()) );

		int numStateBlocks = paddedInput.length / BLOCK_LENGTH;
		int[][][] stateBlocks = new int[numStateBlocks][STATE_ROWS][STATE_COLS];

		for (int i = 0; i < numStateBlocks; i++) {
			/** Process one state block at a time */
			int cpStart = i * BLOCK_LENGTH;
			int cpEnd = cpStart + BLOCK_LENGTH;
			stateBlocks[i] = inputToState(Arrays.copyOfRange(paddedInput, cpStart, cpEnd));
			int[][] state = stateBlocks[i];

			/** AES algorithm */
			addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, BLOCK_LENGTH));
			for (int r = 1; r < numRounds; r++) {
				subBytes(state);
				shiftRows(state);
				mixColumns(state);
				addRoundKey(state, Arrays.copyOfRange(expandedKey, r * BLOCK_LENGTH, (r * BLOCK_LENGTH) + BLOCK_LENGTH));
			}
			subBytes(state);
			shiftRows(state);
			addRoundKey(state, Arrays.copyOfRange(expandedKey, numRounds * BLOCK_LENGTH, (numRounds * BLOCK_LENGTH) + BLOCK_LENGTH));
		
		}

		/* Converting encrypted state matrices back to string representation */
		String cipher = "";
		for (int[][] s : stateBlocks) {
			cipher += matrixToString(s);
		}

		// cipher = hexToString(cipher);
		return cipher;
	}

	/**
     * Performs the decryption of the cipher text
     * @param input ciphertext to be decrypted
     * @return decrypted ciphertext -> plaintext
     */
	public static int[] decrypt(String input, int[] expandedKey, int numRounds) {
		int[] inputArr = convertToIntArray(input.getBytes());

		int numStateBlocks = inputArr.length / BLOCK_LENGTH;
		int[][][] stateBlocks = new int[numStateBlocks][STATE_ROWS][STATE_COLS];

		for (int i = 0; i < numStateBlocks; i++) {
			int cpStart = i * BLOCK_LENGTH;
			int cpEnd = cpStart + BLOCK_LENGTH;
			stateBlocks[i] = inputToState(Arrays.copyOfRange(inputArr, cpStart, cpEnd));
			int[][] state = stateBlocks[i];
			addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, BLOCK_LENGTH));
			for (int r = 1; r < numRounds; r++) {
				shiftRows(state);
				subBytes(state);
				addRoundKey(state, Arrays.copyOfRange(expandedKey, r * BLOCK_LENGTH, (r * BLOCK_LENGTH) + BLOCK_LENGTH));
				mixColumns(state);
			}
			shiftRows(state);
			subBytes(state);
			addRoundKey(state, Arrays.copyOfRange(expandedKey, numRounds * BLOCK_LENGTH, (numRounds * BLOCK_LENGTH) + BLOCK_LENGTH));
		}
		String paddedDecryptedString = matrixToString(stateBlocks[0]);
		byte[] paddedDecryptedByteArr = paddedDecryptedString.getBytes();
		int[] paddedDecryptedIntArr = convertToIntArray(paddedDecryptedByteArr);
		int[] decryptedIntArr = removePadding(paddedDecryptedIntArr);

		return decryptedIntArr;
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
     * Removes padding from output decrypted string to obtain original plaintext
     * @param input Array with padding
     * @return array without padding
     */
    public static int[] removePadding(int[] input) {
    	int paddingLength = input[input.length - 1];
    	int originSize = input.length - paddingLength;
    	int[] origin = Arrays.copyOfRange(input, 0, originSize);
    	return origin;
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
     * Each of the 16 bytes of the state is XORed against each of the 16 bytes of a portion of the expanded 
     * key for the current round
     * @param expKeySlice portion of the expanded key to be XORed with the state
     */
    public static void addRoundKey(int[][] state, int[] expKeySlice) {
    	for (int row = 0; row < STATE_ROWS; row++) {
			state[row] = XOR(state[row], EK(expKeySlice, row * 4));
    	}
    }

	/**
     * Replaces all elements in the passed array with values in sbox[][].
     * @param state Array whose values will be replaced
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
     * Reverses the operations from subBytes by using invsbox
     * @param state Array whose values will be replaced
     */
	public static void invSubBytes(int[][] state) {
		for (int row = 0; row < STATE_ROWS; row++) {
			for (int col = 0; col < STATE_COLS; col++) {
				// hex val is used to determine row/col coords of sbox value
				int hex = state[row][col];
				state[row][col] = invsbox[hex / 16][hex % 16];
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

	/**
     * Shifts 2nd,3rd,4th rows of state by row index
     * @param state Array whose 2nd,3rd,4th rows will be shifted
     */
	public static void invShiftRows(int[][] state) {
		for (int row = 0; row < STATE_ROWS; row++) {
			state[row] = rotateRight(state[row], row);
		}
	}

	/** 
	 * Helper function - shifts an array's cells by 'offset' places to the right
     * @param arr array to be rotated
     * @param offset number of right rotations
     * @return rotated array
     */
	public static int[] rotateRight(int[] arr, int offset) {
		// will yield same arr
		if (offset % 4 == 0) {
			return arr;
		}
		while (offset > 0) {
			int temp = arr[arr.length-1];
			for (int i = arr.length-1; i > 0; i--) {
				arr[i] = arr[i-1];
			}
			arr[0] = temp;
			offset--;
		}
		return arr;
	}

	/**
     * Each element in the current state is replaced with a value based on an operation
     * in the mc helper functions.
     * @param state the state matrix that will be multiplied against the galois field
     */
	public static void mixColumns(int[][] state) {
		int[][] tState = new int[STATE_ROWS][STATE_COLS];
		// make copy of state as we will be overwriting state throughout loop iterations
		for(int i = 0; i < STATE_ROWS; i++)
        {
            System.arraycopy(state[i], 0, tState[i], 0, STATE_COLS);
        }
		for (int i = 0; i < STATE_ROWS; i++) {
			for (int j = 0; j < STATE_COLS; j++) {
				state[i][j] = mcCellCalc(tState, galois, i, j);
			}
		}
	}

	/**
     * Performs the multiplication of the state cell with the respective galois field cell
     * @param tState a copy of the state matrix
     * @param i,j row,col indexes 
     */
	public static int mcCellCalc(int[][] tState, int[][] g, int i, int j) {
		int cellVal = 0;
		// extra k loop helps travers galois row and tState col at same rate
		for (int k = 0; k < STATE_ROWS; k++){
			int gCell = g[i][k];
			int sCell = tState[k][j];
			cellVal ^= mcLookup(gCell, sCell);
		}
		return cellVal;
	}

	/**
     * Result of the multiplication is simply the result of a lookup of the L table, followed by the addition of the
	 * results, followed by a lookup to the E table.
     * @param gVal,sVal cell values taken from galois field and tState used to look up value from LTable and ETable
     */
	public static int mcLookup(int gVal, int sVal) {
		// sVal multiplied by 1 is itself so only lookup sVal
		if (gVal == 0x01) {
			int l = LTable[sVal / 16][sVal % 16];
			return ETable[l / 16][l % 16];
		}
		int l1 = LTable[gVal / 16][gVal % 16];
		int l2 = LTable[sVal / 16][sVal % 16];
		int lTemp = l1 + l2;
		int lsum = lTemp > 0xFF ? lTemp - 0xFF : lTemp;
		int e = ETable[lsum / 16][lsum % 16];
		return e;
	}

	/**
     * Other then the change to the galois table the function performs the same steps as during encryption.
     * @param state the state matrix that will be multiplied against the galois field
     */
	public static void invMixColumns(int[][] state) {
		int[][] tState = new int[STATE_ROWS][STATE_COLS];
		// make copy of state as we will be overwriting state throughout loop iterations
		for(int i = 0; i < STATE_ROWS; i++)
        {
            System.arraycopy(state[i], 0, tState[i], 0, STATE_COLS);
        }
		for (int i = 0; i < STATE_ROWS; i++) {
			for (int j = 0; j < STATE_COLS; j++) {
				state[i][j] = mcCellCalc(tState, invgalois, i, j);
			}
		}
	}

	/**
     * Prior to encryption or decryption the key must be expanded. The expanded key is used in the Add Round Key function.
     * @param key the secret key to be expanded
     * @param numAESRounds the number of encryption rounds based on key size (128->10, 192->12, 256->14)
     * @param numExpRounds the number of key expansion rounds
     * @return the expanded key
     */
	public static int[] expandKey(int[] key, int numAESRounds, int numExpRounds) {
		int ekSize = 16 * (numAESRounds + 1); // 16 is the size of the block in bytes.
		int[] ek = new int[ekSize];
		int nk = key.length / 4; //will only be 4, 6 or 8 -> 16(bytes)/4, 24/4 or 32/4

        System.arraycopy(key, 0, ek, 0, key.length); // Acts as 4 calls to k() : The first bytes of the expanded key are always equal to the key.

        int round = key.length / 4;
        while (round < numExpRounds) {
        	int[] temp = EK(ek, (round - 1) * 4);
        	if (round % nk == 0) {
				temp = XOR(subWord(rotWord(temp)), rcon(round, key.length));
        	} else if (nk > 6 && round % nk == 4) {
        		temp = subWord(temp);
        	}
        	temp = XOR(temp, EK(ek, (round - nk) * 4));
        	System.arraycopy(temp, 0, ek, round*4, temp.length);
        	round++;
        }
        return ek;
	}

	/**
     * Rotates an array to the left by one 
     * @param arr array to be rotated
     * @return rotated array
     */
	public static int[] rotWord(int[] arr) {
		return rotateLeft(arr, 1);
	}

	/**
     * Applies the S-box value substitution as described in Bytes Sub function to each of the 4 bytes in the argument.
     * @param arr values used to sample sbox table
     * @return array of sampled sbox values
     */
	public static int[] subWord(int[] arr) {
		for (int i = 0; i < STATE_COLS; i++) {
			int hex = arr[i];
			arr[i] = sbox[hex / 16][hex % 16];
		}
		return arr;
	}

	/**
     * This function returns a 4 int array based on the rcon table
     * @param roundNum,keySize used to determine index used to sample value from rcon table
     * @return 4 int array with value sampled from rcon table followed by 0x00s
     */
	public static int[] rcon(int roundNum, int keySize) {
		int[] arr = new int[4]; // all values initialized to 0x00;
		int index = (roundNum / (keySize / 4)) - 1;
		arr[0] = rconTable[index]; // only first element is updated based on lookup
		return arr;
	}

	/**
     * Returns 4 elements of the Expanded Key after the specified offset.
     * @param offset marks the index to start sampling
     * @return 4 elements of the Expanded Key
     */
	public static int[] EK(int[] expandedKey, int offset) {
		int[] subEK = {expandedKey[offset], expandedKey[offset + 1], expandedKey[offset + 2], expandedKey[offset + 3]};
		return subEK;
	}

	/**
     * Returns 4 elements of the Key after the specified offset.
     * @param offset marks the index to start sampling
     * @return 4 elements of the Key
     */
	public static int[] K(int[] key, int offset) {
		int[] subK = {key[offset], key[offset + 1], key[offset + 2], key[offset + 3]};
		return subK;
	}

	/**
     * Performs XOR operation on two arrays
     * @param a,b arrays to be XORed
     * @return an array that is the result of XORing a and b
     */
	public static int[] XOR(int[] a, int[] b) {
		int[] c = new int[a.length];
		for (int i = 0; i < a.length; i++){
			c[i] = a[i] ^ b[i];
		}
		return c;
	}


	public static int[] convertToIntArray(byte[] input) {
	    int[] ret = new int[input.length];
	    for (int i = 0; i < input.length; i++)
	    {
	        ret[i] = input[i] & 0xFF; // Range 0 to 255, not -128 to 127. Without 0xFF, table lookups yield indexOutOfBounds due to negative values
	    }
	    return ret;
	}

	public static String matrixToString(int[][] m) //takes in a matrix and converts it into a line of 32 hex characters.
    {
        String t = "";
        for (int i = 0; i < m.length; i++) {
            for (int j = 0; j < m[0].length; j++) {
                String h = Integer.toHexString(m[j][i]).toUpperCase();
                if (h.length() == 1) {
                    t += '0' + h;
                } else {
                    t += h;
                }
            }
        }
        return t;
    }

    public static String hexToString(String hex) {
	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    for (int i = 0; i < hex.length(); i += 2) {
	      String str = hex.substring(i, i + 2);
	      int byteVal = Integer.parseInt(str, 16);
	      baos.write(byteVal);
	    } 
	    String s = new String(baos.toByteArray(), Charset.forName("UTF-8"));
	    return s;
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