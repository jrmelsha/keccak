package com.joemelsha.crypto.hash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;

/**
 * @author Joseph Robert Melsha (jrmelsha@olivet.edu)
 *
 * Source: https://github.com/jrmelsha/keccak
 * Created: Jun 23, 2016
 *
 * Copyright 2016 Joseph Robert Melsha
 * Changed by Evan Saulpaugh
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
public class Keccak extends MessageDigest {

	private static final int MAX_STATE_SIZE = 1600;
	private static final int MAX_STATE_SIZE_WORDS = MAX_STATE_SIZE / 64;

	protected final int digestSizeBits;
	protected final transient int digestSizeBytes;
	protected final transient int rateSizeBits;
	private final transient int rateSizeWords;

	private final long[] state = new long[MAX_STATE_SIZE_WORDS];
	private int rateBits = 0;

	protected transient ByteBuffer out;

	public Keccak(int digestSizeBits) {
		this("Keccak-", digestSizeBits);
	}

	protected Keccak(String variantPrefix, int digestSizeBits) {
		super(variantPrefix + digestSizeBits);
		int rateSizeBits = rateSizeBitsFor(digestSizeBits);
		if (rateSizeBits + digestSizeBits * 2 != MAX_STATE_SIZE)
			throw new IllegalArgumentException("Invalid rateSizeBits + digestSizeBits * 2: " + rateSizeBits + " + " + digestSizeBits + " * 2 != " + MAX_STATE_SIZE);
		if (rateSizeBits <= 0 || (rateSizeBits & 0x3f) != 0)
			throw new IllegalArgumentException("Invalid rateSizeBits: " + rateSizeBits);

		this.digestSizeBits = digestSizeBits;
		this.digestSizeBytes = digestSizeBits >>> 3;

		this.rateSizeBits = rateSizeBits;
		this.rateSizeWords = rateSizeBits >>> 6;
	}

	public Keccak(Keccak other) {
		super(other.getAlgorithm());
		System.arraycopy(other.state, 0, state, 0, other.state.length);
		this.digestSizeBits = other.digestSizeBits;
		this.rateSizeBits = other.rateSizeBits;

		this.digestSizeBytes = digestSizeBits >>> 3;
		this.rateSizeWords = rateSizeBits >>> 6;

		this.rateBits = other.rateBits;
	}

	public int rateSize() {
		return rateSizeBits >>> 3;
	}

	protected int rateSizeBitsFor(int digestSizeBits) {
		switch (digestSizeBits) {
		case 128: return 1344;
		case 224: return 1152;
		case 256: return 1088;
		case 288: return 1024;
		case 384: return  832;
		case 512: return  576;
		default: throw new IllegalArgumentException("Invalid digestSizeBits: " + digestSizeBits + " ⊄ { 128, 224, 256, 288, 384, 512 }");
		}
	}

	@Override
	protected void engineReset() {

		for (int i = 0; i < MAX_STATE_SIZE_WORDS; i++) {
			state[i] = 0L;
		}

		rateBits = 0;
		out = null;
	}

	@Override
	protected int engineGetDigestLength() {
		return digestSizeBytes;
	}

	@Override
	protected void engineUpdate(byte input) {
		updateBits(input & 0xFFL, 8);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		engineUpdate(ByteBuffer.wrap(input, offset, len));
	}

	@Override
	protected void engineUpdate(ByteBuffer in) {

		int remaining = in.remaining();
		if (remaining <= 0) {
			return;
		}

		int rateBits = this.rateBits;
		if ((rateBits & 0x7) != 0) { // 0b111
			throw new IllegalStateException("Cannot update while in bit mode");
		}

		long[] state = this.state;
		int rateBytes = rateBits >>> 3;

		int rateBytesWord = rateBytes & 0x7; // 0b111
		if (rateBytesWord > 0) {
			int c = 8 - rateBytesWord;
			if (c > remaining)
				c = remaining;
			int i = rateBytes >>> 3;
			long w = state[i];
			rateBytes += c;
			remaining -= c;
			rateBytesWord <<= 3;
			c = rateBytesWord + (c << 3);

			do {
				w ^= (in.get() & 0xFFL) << rateBytesWord;
				rateBytesWord += 8;
			} while (rateBytesWord < c);

			state[i] = w;
			this.rateBits = rateBytes << 3;
			if (remaining <= 0) {
				return;
			}
		}

		int rateWords = rateBytes >>> 3;
		int inWords = remaining >>> 3;
		if (inWords > 0) {
			ByteOrder order = in.order();
			try {
				in.order(ByteOrder.LITTLE_ENDIAN);
				do {
					if (rateWords >= rateSizeWords) {
						keccak(state);
						rateWords = 0;
					}
					int c = rateSizeWords - rateWords;
					if (c > inWords)
						c = inWords;
					inWords -= c;
					c += rateWords;
					do {
						state[rateWords++] ^= in.getLong();
					} while (rateWords < c);
				} while (inWords > 0);
			} finally {
				in.order(order);
			}
			this.rateBits = rateWords << 6;
			remaining &= 0x7; // 0b111
		}

		if (rateWords >= rateSizeWords) {
			keccak(state);
			this.rateBits = 0;
			rateWords = 0;
		}

		if (remaining > 0) {
			long w = state[rateWords];
			final int remainingBits = remaining << 3; // remaining in [1, 7]
			int shiftAmount = 0;
			switch (remaining) {
			case 7: w ^= in.get() & 0xFFL; shiftAmount = Byte.SIZE;
			case 6: w ^= (in.get() & 0xFFL) << shiftAmount; shiftAmount += Byte.SIZE;
			case 5: w ^= (in.get() & 0xFFL) << shiftAmount; shiftAmount += Byte.SIZE;
			case 4: w ^= (in.get() & 0xFFL) << shiftAmount; shiftAmount += Byte.SIZE;
			case 3: w ^= (in.get() & 0xFFL) << shiftAmount; shiftAmount += Byte.SIZE;
			case 2: w ^= (in.get() & 0xFFL) << shiftAmount; shiftAmount += Byte.SIZE;
			case 1: w ^= (in.get() & 0xFFL) << shiftAmount;
			}

			state[rateWords] = w;
			this.rateBits += remainingBits;
		}
	}

	public void digest(ByteBuffer out, int len) {
		final int prevLim = out.limit();
		out.limit(out.position() + len);
		digest(out);
		out.limit(prevLim);
	}

	public void digest(ByteBuffer out) {
		this.out = out;
		engineDigest();
	}

	@Override
	protected int engineDigest(byte[] buf, int offset, int len) {
		out = ByteBuffer.wrap(buf, offset, len);
		engineDigest();
		return len;
	}

	@Override
	protected byte[] engineDigest() {

		pad();

		int remaining;
		if(out != null) {
			remaining = out.remaining();
		} else {
			out = ByteBuffer.allocate(digestSizeBytes);
			remaining = digestSizeBytes;
		}

		int rateWords = 0;
		int outWords = remaining >>> 3;
		if (outWords > 0) {
			out.order(ByteOrder.LITTLE_ENDIAN);
			do {
				if (rateWords >= rateSizeWords) {
					keccak(state); // squeeze
					rateWords = 0;
				}
				int c = rateSizeWords - rateWords;
				if (c > outWords)
					c = outWords;
				outWords -= c;
				c += rateWords;
				do {
					out.putLong(state[rateWords]);
					rateWords++;
				} while (rateWords < c);
			} while (outWords > 0);
			remaining &= 0x7; // 0b111
		}

		if (remaining > 0) {
			if (rateWords >= rateSizeWords) {
				keccak(state); // squeeze
				rateWords = 0;
			}
			long w = state[rateWords];

			int shiftAmount = 0;
			switch (remaining) {
			case 7: out.put((byte) w); shiftAmount = Byte.SIZE;
			case 6: out.put((byte) (w >>> shiftAmount)); shiftAmount += Byte.SIZE;
			case 5: out.put((byte) (w >>> shiftAmount)); shiftAmount += Byte.SIZE;
			case 4: out.put((byte) (w >>> shiftAmount)); shiftAmount += Byte.SIZE;
			case 3: out.put((byte) (w >>> shiftAmount)); shiftAmount += Byte.SIZE;
			case 2: out.put((byte) (w >>> shiftAmount)); shiftAmount += Byte.SIZE;
			case 1: out.put((byte) (w >>> shiftAmount));
			}
		}

		try {
			return out.array();
		} finally {
			engineReset();
		}
	}

	protected void pad() {
//        updateBits(0x6L, 3); // SHA-3 padding:011 (little-endian) = 0x6
		updateBits(0x1L, 1); // Keccak padding: 1
		if (rateBits >= rateSizeBits) {
			keccak(state);
		}
		rateBits = rateSizeBits - 1;
		updateBits(0x1L, 1);
		keccak(state);
	}

	protected void updateBits(long in, int inBits) {

//        if (inBits < 0 || inBits > 64)
//            throw new IllegalArgumentException("Invalid valueBits: " + 0 + " < " + inBits + " > " + 64);

		if (inBits <= 0)
			return;

		int rateBits = this.rateBits;
		int rateBitsWord = rateBits & 0x3f;
		if (rateBitsWord > 0) {
			int c = 64 - rateBitsWord;
			if (c > inBits)
				c = inBits;
			state[rateBits >>> 6] ^= (in & (-1L >>> c)) << rateBitsWord;
			rateBits += c;
			inBits -= c;
			if (inBits <= 0) {
				this.rateBits = rateBits;
				return;
			}
			in >>>= c;
		}
		if (rateBits >= rateSizeBits) {
			keccak(state);
//            rateBits = 0;
			state[0] ^= in & (-1L >>> inBits);
			this.rateBits = inBits;
			return;
		}
		state[rateBits >>> 6] ^= in & (-1L >>> inBits);
		this.rateBits = rateBits + inBits;
	}

	private static void keccak(long[] a) {
		long x, a_10_;
		long x0, x1, x2, x3, x4;
		long t0, t1, t2, t3, t4;
		long c0, c1, c2, c3, c4;

		int i = 0;
		do {
			// theta (precalculation part)
			c0 = a[0] ^ a[5 + 0] ^ a[10 + 0] ^ a[15 + 0] ^ a[20 + 0];
			c1 = a[1] ^ a[5 + 1] ^ a[10 + 1] ^ a[15 + 1] ^ a[20 + 1];
			c2 = a[2] ^ a[5 + 2] ^ a[10 + 2] ^ a[15 + 2] ^ a[20 + 2];
			c3 = a[3] ^ a[5 + 3] ^ a[10 + 3] ^ a[15 + 3] ^ a[20 + 3];
			c4 = a[4] ^ a[5 + 4] ^ a[10 + 4] ^ a[15 + 4] ^ a[20 + 4];

			t0 = (c0 << 1) ^ (c0 >>> (64 - 1)) ^ c3;
			t1 = (c1 << 1) ^ (c1 >>> (64 - 1)) ^ c4;
			t2 = (c2 << 1) ^ (c2 >>> (64 - 1)) ^ c0;
			t3 = (c3 << 1) ^ (c3 >>> (64 - 1)) ^ c1;
			t4 = (c4 << 1) ^ (c4 >>> (64 - 1)) ^ c2;

			// theta (xorring part) + rho + pi
			a[ 0] ^= t1;
			x = a[ 1] ^ t2; a_10_ = (x <<  1) | (x >>> (64 -  1));
			x = a[ 6] ^ t2; a[ 1] = (x << 44) | (x >>> (64 - 44));
			x = a[ 9] ^ t0; a[ 6] = (x << 20) | (x >>> (64 - 20));
			x = a[22] ^ t3; a[ 9] = (x << 61) | (x >>> (64 - 61));

			x = a[14] ^ t0; a[22] = (x << 39) | (x >>> (64 - 39));
			x = a[20] ^ t1; a[14] = (x << 18) | (x >>> (64 - 18));
			x = a[ 2] ^ t3; a[20] = (x << 62) | (x >>> (64 - 62));
			x = a[12] ^ t3; a[ 2] = (x << 43) | (x >>> (64 - 43));
			x = a[13] ^ t4; a[12] = (x << 25) | (x >>> (64 - 25));

			x = a[19] ^ t0; a[13] = (x <<  8) | (x >>> (64 -  8));
			x = a[23] ^ t4; a[19] = (x << 56) | (x >>> (64 - 56));
			x = a[15] ^ t1; a[23] = (x << 41) | (x >>> (64 - 41));
			x = a[ 4] ^ t0; a[15] = (x << 27) | (x >>> (64 - 27));
			x = a[24] ^ t0; a[ 4] = (x << 14) | (x >>> (64 - 14));

			x = a[21] ^ t2; a[24] = (x <<  2) | (x >>> (64 -  2));
			x = a[ 8] ^ t4; a[21] = (x << 55) | (x >>> (64 - 55));
			x = a[16] ^ t2; a[ 8] = (x << 45) | (x >>> (64 - 45));
			x = a[ 5] ^ t1; a[16] = (x << 36) | (x >>> (64 - 36));
			x = a[ 3] ^ t4; a[ 5] = (x << 28) | (x >>> (64 - 28));

			x = a[18] ^ t4; a[ 3] = (x << 21) | (x >>> (64 - 21));
			x = a[17] ^ t3; a[18] = (x << 15) | (x >>> (64 - 15));
			x = a[11] ^ t2; a[17] = (x << 10) | (x >>> (64 - 10));
			x = a[ 7] ^ t3; a[11] = (x <<  6) | (x >>> (64 -  6));
			x = a[10] ^ t1; a[ 7] = (x <<  3) | (x >>> (64 -  3));
//            a[10] = a_10_;

			// chi
			x0 = a[0]; x1 = a[1]; x2 = a[2]; x3 = a[3]; x4 = a[4];
			a[0] = x0 ^ ((~x1) & x2);
			a[1] = x1 ^ ((~x2) & x3);
			a[2] = x2 ^ ((~x3) & x4);
			a[3] = x3 ^ ((~x4) & x0);
			a[4] = x4 ^ ((~x0) & x1);

			x0 = a[5]; x1 = a[6]; x2 = a[7]; x3 = a[8]; x4 = a[9];
			a[5] = x0 ^ ((~x1) & x2);
			a[6] = x1 ^ ((~x2) & x3);
			a[7] = x2 ^ ((~x3) & x4);
			a[8] = x3 ^ ((~x4) & x0);
			a[9] = x4 ^ ((~x0) & x1);

			x0 = a_10_; x1 = a[11]; x2 = a[12]; x3 = a[13]; x4 = a[14];
			a[10] = x0 ^ ((~x1) & x2);
			a[11] = x1 ^ ((~x2) & x3);
			a[12] = x2 ^ ((~x3) & x4);
			a[13] = x3 ^ ((~x4) & x0);
			a[14] = x4 ^ ((~x0) & x1);

			x0 = a[15]; x1 = a[16]; x2 = a[17]; x3 = a[18]; x4 = a[19];
			a[15] = x0 ^ ((~x1) & x2);
			a[16] = x1 ^ ((~x2) & x3);
			a[17] = x2 ^ ((~x3) & x4);
			a[18] = x3 ^ ((~x4) & x0);
			a[19] = x4 ^ ((~x0) & x1);

			x0 = a[20]; x1 = a[21]; x2 = a[22]; x3 = a[23]; x4 = a[24];
			a[20] = x0 ^ ((~x1) & x2);
			a[21] = x1 ^ ((~x2) & x3);
			a[22] = x2 ^ ((~x3) & x4);
			a[23] = x3 ^ ((~x4) & x0);
			a[24] = x4 ^ ((~x0) & x1);

			// iota
			switch (i) {
			case 0: a[0] ^= 0x0000000000000001L; break;
			case 1: a[0] ^= 0x0000000000008082L; break;
			case 2: a[0] ^= 0x800000000000808AL; break;
			case 3: a[0] ^= 0x8000000080008000L; break;
			case 4: a[0] ^= 0x000000000000808BL; break;

			case 5: a[0] ^= 0x0000000080000001L; break;
			case 6: a[0] ^= 0x8000000080008081L; break;
			case 7: a[0] ^= 0x8000000000008009L; break;
			case 8: a[0] ^= 0x000000000000008AL; break;
			case 9: a[0] ^= 0x0000000000000088L; break;

			case 10: a[0] ^= 0x0000000080008009L; break;
			case 11: a[0] ^= 0x000000008000000AL; break;
			case 12: a[0] ^= 0x000000008000808BL; break;
			case 13: a[0] ^= 0x800000000000008BL; break;
			case 14: a[0] ^= 0x8000000000008089L; break;

			case 15: a[0] ^= 0x8000000000008003L; break;
			case 16: a[0] ^= 0x8000000000008002L; break;
			case 17: a[0] ^= 0x8000000000000080L; break;
			case 18: a[0] ^= 0x000000000000800AL; break;
			case 19: a[0] ^= 0x800000008000000AL; break;

			case 20: a[0] ^= 0x8000000080008081L; break;
			case 21: a[0] ^= 0x8000000000008080L; break;
			case 22: a[0] ^= 0x0000000080000001L; break;
			case 23: a[0] ^= 0x8000000080008008L;
			}

			i++;
		} while (i < 24);
	}
}
