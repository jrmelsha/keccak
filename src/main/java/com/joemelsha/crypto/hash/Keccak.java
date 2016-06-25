package com.joemelsha.crypto.hash;

import java.nio.*;

/**
 * @author Joseph Robert Melsha (jrmelsha@olivet.edu)
 *
 * Source: https://github.com/jrmelsha/keccak
 * Created: Jun 23, 2016
 *
 * Copyright 2016 Joseph Robert Melsha
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
public class Keccak {
	private static final int MAX_STATE_SIZE = 1600;
	private static final int MAX_STATE_SIZE_WORDS = MAX_STATE_SIZE / 64;

	protected int rateSizeBits, digestSizeBits;
	private long[] state = new long[MAX_STATE_SIZE_WORDS];
	private int rateBits;
	private boolean padded;

	public Keccak(int digestSizeBits) {
		reset(digestSizeBits);
	}

	public Keccak(Keccak other) {
		System.arraycopy(other.state, 0, state, 0, other.state.length);
		rateBits = other.rateBits;
		rateSizeBits = other.rateSizeBits;
		digestSizeBits = other.digestSizeBits;
		padded = other.padded;
	}

	@Override
	public String toString() {
		return "Keccak-" + digestSizeBits;
	}

	public int rateSize() {
		return rateSizeBits >>> 3;
	}

	public int digestSize() {
		return digestSizeBits >>> 3;
	}

	public void reset() {
		reset(rateSizeBits, digestSizeBits);
	}

	protected int rateSizeBitsFor(int digestSizeBits) {
		//@formatter:off
		switch (digestSizeBits) {
			case 288: return 1024;
			case 128: return 1344;
			case 224: return 1152;
			case 256: return 1088;
			case 384: return  832;
			case 512: return  576;
			default: throw new IllegalArgumentException("Invalid digestSizeBits: " + digestSizeBits + " ⊄ { 128, 224, 256, 288, 384, 512 }");
		}
		//@formatter:on
	}

	public void reset(int digestSizeBits) {
		reset(rateSizeBitsFor(digestSizeBits), digestSizeBits);
	}

	protected void reset(int rateSizebits, int digestSizeBits) {
		if (rateSizebits + digestSizeBits * 2 != MAX_STATE_SIZE)
			throw new IllegalArgumentException("Invalid rateSizebits + digestSizeBits * 2: " + rateSizebits + " + " + digestSizeBits + " * 2 != " + MAX_STATE_SIZE);
		if (rateSizebits <= 0 || (rateSizebits & 0x3f) > 0)
			throw new IllegalArgumentException("Invalid rateSizebits: " + rateSizebits);

		for (int i = 0; i < MAX_STATE_SIZE_WORDS; ++i)
			state[i] = 0;
		rateBits = 0;

		rateSizeBits = rateSizebits;
		this.digestSizeBits = digestSizeBits;
		padded = false;
	}

	public void update(byte in) {
		updateBits(in & 0xff, 8);
	}

	public void update(byte[] in) {
		update(ByteBuffer.wrap(in));
	}

	public void update(byte[] in, int offset, int length) {
		update(ByteBuffer.wrap(in, offset, length));
	}

	public void update(ByteBuffer in) {
		int inBytes = in.remaining();
		if (inBytes <= 0)
			return;

		if (padded)
			throw new IllegalStateException("Cannot update while padded");

		int rateBits = this.rateBits;
		if ((rateBits & 0x7) > 0) //this could be implemented but would introduce considerable performance degradation - also, it's never technically possible.
			throw new IllegalStateException("Cannot update while in bit-mode");

		long[] state = this.state;
		int rateBytes = rateBits >>> 3;

		int rateBytesWord = rateBytes & 0x7;
		if (rateBytesWord > 0) {
			//logically must have space at this point
			int c = 8 - rateBytesWord;
			if (c > inBytes)
				c = inBytes;
			int i = rateBytes >>> 3;
			long w = state[i];
			rateBytes += c;
			inBytes -= c;
			rateBytesWord <<= 3;
			c = rateBytesWord + (c << 3);
			do {
				w ^= (long) (in.get() & 0xff) << rateBytesWord;
				rateBytesWord += 8;
			} while (rateBytesWord < c);
			state[i] = w;

			if (inBytes > 0) {
				this.rateBits = rateBytes << 3;
				return;
			}
		}

		int rateWords = rateBytes >>> 3;
		int rateSizeWords = rateSizeBits >>> 6;

		int inWords = inBytes >>> 3;
		if (inWords > 0) {
			ByteOrder order = in.order();
			try {
				in.order(ByteOrder.LITTLE_ENDIAN);
				do {
					if (rateWords >= rateSizeWords) {
						Keccak.keccak(state);
						rateWords = 0;
					}
					int c = rateSizeWords - rateWords;
					if (c > inWords)
						c = inWords;
					inWords -= c;
					c += rateWords;
					do {
						state[rateWords] ^= in.getLong();
						rateWords++;
					} while (rateWords < c);
				} while (inWords > 0);
			} finally {
				in.order(order);
			}
			inBytes &= 0x7;
			if (inBytes <= 0) {
				this.rateBits = rateWords << 6;
				return;
			}
		}

		if (rateWords >= rateSizeWords) {
			Keccak.keccak(state);
			rateWords = 0;
		}
		long w = state[rateWords];
		inBytes <<= 3;
		int i = 0;
		do {
			w ^= (long) (in.get() & 0xff) << i;
			i += 8;
		} while (i < inBytes);
		state[rateWords] = w;

		this.rateBits = (rateWords << 6) | inBytes;
	}

	protected void updateBits(long in, int inBits) {
		if (inBits < 0 || inBits > 64)
			throw new IllegalArgumentException("Invalid valueBits: " + 0 + " < " + inBits + " > " + 64);

		if (inBits <= 0)
			return;

		if (padded)
			throw new IllegalStateException("Cannot update while padded");

		long[] state = this.state;
		int rateBits = this.rateBits;
		int rateBitsWord = rateBits & 0x3f;
		if (rateBitsWord > 0) {
			//logically must have space at this point
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
			Keccak.keccak(state);
			rateBits = 0;
		}
		state[rateBits >>> 6] ^= in & (-1L >>> inBits);
		this.rateBits = rateBits + inBits;
	}

	public ByteBuffer digest() {
		return digest(digestSize());
	}

	public ByteBuffer digest(int outSize) {
		return digest(outSize, false);
	}

	public ByteBuffer digest(int outSize, boolean direct) {
		ByteBuffer buffer = direct ? ByteBuffer.allocateDirect(outSize) : ByteBuffer.allocate(outSize);
		digest(buffer);
		return buffer;
	}

	public byte[] digestArray() {
		return digestArray(digestSize());
	}

	public byte[] digestArray(int outSize) {
		byte[] array = new byte[outSize];
		digest(array, 0, outSize);
		return array;
	}

	public void digest(byte[] out) {
		digest(ByteBuffer.wrap(out));
	}

	public void digest(byte[] out, int offset, int length) {
		digest(ByteBuffer.wrap(out, offset, length));
	}

	public void digest(ByteBuffer out) {
		int outBytes = out.remaining();
		if (outBytes <= 0)
			return;

		long[] state = this.state;
		int rateBits = this.rateBits;
		int rateBytes;
		if (!padded) {
			pad();
			padded = true;
			rateBits = 0;
			rateBytes = 0;
		} else {
			if ((rateBits & 0x7) > 0)
				throw new IllegalStateException("Cannot digest while in bit-mode"); //this could be implemented but would introduce considerable performance degradation - also, it's never technically possible.

			rateBytes = rateBits >>> 3;
			int rateBytesWord = rateBytes & 0x7;
			if (rateBytesWord > 0) {
				int c = 8 - rateBytesWord;
				if (c > outBytes)
					c = outBytes;
				long w = state[rateBytes >>> 3];
				outBytes -= c;
				rateBytes += c;
				rateBytesWord <<= 3;
				c = (c << 3) + rateBytesWord;
				do {
					out.put((byte) (w >>> rateBytesWord));
					rateBytesWord += 8;
				} while (rateBytesWord < c);
				if (outBytes <= 0) {
					this.rateBits = rateBytes << 3;
					return;
				}
			}
		}

		int rateSizeWords = rateSizeBits >>> 6;
		int rateWords = rateBytes >>> 3;

		int outWords = outBytes >>> 3;
		if (outWords > 0) {
			ByteOrder order = out.order();
			try {
				out.order(ByteOrder.LITTLE_ENDIAN);
				do {
					if (rateWords >= rateSizeWords) {
						squeeze();
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
			} finally {
				out.order(order);
			}
			outBytes &= 0x7;
			if (outBytes <= 0) {
				this.rateBits = rateWords << 6;
				return;
			}
		}

		if (rateWords >= rateSizeWords) {
			squeeze();
			rateWords = 0;
		}
		long w = state[rateWords];
		outBytes <<= 3;
		int i = 0;
		do {
			out.put((byte) (w >>> i));
			i += 8;
		} while (i < outBytes);
		this.rateBits = (rateWords << 6) | outBytes;
	}

	protected void squeeze() {
		Keccak.keccak(state);
	}

	protected void pad() {
		updateBits(0x1, 1);
		if (rateBits >= rateSizeBits) {
			Keccak.keccak(state);
			rateBits = 0;
		}
		rateBits = rateSizeBits - 1;
		updateBits(0x1, 1);
		Keccak.keccak(state);
	}

	private static void keccak(long[] a) {
		//@formatter:off
		long a_0 = a[ 0], a_1 = a[ 1], a_2 = a[ 2], a_3 = a[ 3], a_4 = a[ 4],
			 a_5 = a[ 5], a_6 = a[ 6], a_7 = a[ 7], a_8 = a[ 8], a_9 = a[ 9],
			 a10 = a[10], a11 = a[11], a12 = a[12], a13 = a[13], a14 = a[14],
			 a15 = a[15], a16 = a[16], a17 = a[17], a18 = a[18], a19 = a[19],
			 a20 = a[20], a21 = a[21], a22 = a[22], a23 = a[23], a24 = a[24];
		long[] rc = RC;

		long t0, t1, t2, t3, t4;
		long c0, c1, c2, c3, c4;
		long p10;

		int i = 0;
		do {
			//theta (pre)
			c0 = a_0 ^ a_5 ^ a10 ^ a15 ^ a20;
			c1 = a_1 ^ a_6 ^ a11 ^ a16 ^ a21;
			c2 = a_2 ^ a_7 ^ a12 ^ a17 ^ a22;
			c3 = a_3 ^ a_8 ^ a13 ^ a18 ^ a23;
			c4 = a_4 ^ a_9 ^ a14 ^ a19 ^ a24;

			t0 = c4 ^ (c1 << 1) ^ (c1 >>> (64 - 1));
			t1 = c0 ^ (c2 << 1) ^ (c2 >>> (64 - 1));
			t2 = c1 ^ (c3 << 1) ^ (c3 >>> (64 - 1));
			t3 = c2 ^ (c4 << 1) ^ (c4 >>> (64 - 1));
			t4 = c3 ^ (c0 << 1) ^ (c0 >>> (64 - 1));

			//theta (post) + pi + rho
			a_0 ^= t0; p10 = a10;
			a_1 ^= t1; a10 = (a_1 <<  1) | (a_1 >>> (64 -  1));
			a_6 ^= t1; a_1 = (a_6 << 44) | (a_6 >>> (64 - 44));
			a_9 ^= t4; a_6 = (a_9 << 20) | (a_9 >>> (64 - 20));
			a22 ^= t2; a_9 = (a22 << 61) | (a22 >>> (64 - 61));

			a14 ^= t4; a22 = (a14 << 39) | (a14 >>> (64 - 39));
			a20 ^= t0; a14 = (a20 << 18) | (a20 >>> (64 - 18));
			a_2 ^= t2; a20 = (a_2 << 62) | (a_2 >>> (64 - 62));
			a12 ^= t2; a_2 = (a12 << 43) | (a12 >>> (64 - 43));
			a13 ^= t3; a12 = (a13 << 25) | (a13 >>> (64 - 25));

			a19 ^= t4; a13 = (a19 <<  8) | (a19 >>> (64 -  8));
			a23 ^= t3; a19 = (a23 << 56) | (a23 >>> (64 - 56));
			a15 ^= t0; a23 = (a15 << 41) | (a15 >>> (64 - 41));
			a_4 ^= t4; a15 = (a_4 << 27) | (a_4 >>> (64 - 27));
			a24 ^= t4; a_4 = (a24 << 14) | (a24 >>> (64 - 14));

			a21 ^= t1; a24 = (a21 <<  2) | (a21 >>> (64 -  2));
			a_8 ^= t3; a21 = (a_8 << 55) | (a_8 >>> (64 - 55));
			a16 ^= t1; a_8 = (a16 << 45) | (a16 >>> (64 - 45));
			a_5 ^= t0; a16 = (a_5 << 36) | (a_5 >>> (64 - 36));
			a_3 ^= t3; a_5 = (a_3 << 28) | (a_3 >>> (64 - 28));

			a18 ^= t3; a_3 = (a18 << 21) | (a18 >>> (64 - 21));
			a17 ^= t2; a18 = (a17 << 15) | (a17 >>> (64 - 15));
			a11 ^= t1; a17 = (a11 << 10) | (a11 >>> (64 - 10));
			a_7 ^= t2; a11 = (a_7 <<  6) | (a_7 >>> (64 -  6));
			p10 ^= t0; a_7 = (p10 <<  3) | (p10 >>> (64 -  3));

			//chi
			c0 = a_0 ^ ((~a_1) & a_2);
			c1 = a_1 ^ ((~a_2) & a_3);
			a_2 = a_2 ^ ((~a_3) & a_4);
			a_3 = a_3 ^ ((~a_4) & a_0);
			a_4 = a_4 ^ ((~a_0) & a_1);
			a_0 = c0;
			a_1 = c1;

			c0 = a_5 ^ ((~a_6) & a_7);
			c1 = a_6 ^ ((~a_7) & a_8);
			a_7 = a_7 ^ ((~a_8) & a_9);
			a_8 = a_8 ^ ((~a_9) & a_5);
			a_9 = a_9 ^ ((~a_5) & a_6);
			a_5 = c0;
			a_6 = c1;

			c0 = a10 ^ ((~a11) & a12);
			c1 = a11 ^ ((~a12) & a13);
			a12 = a12 ^ ((~a13) & a14);
			a13 = a13 ^ ((~a14) & a10);
			a14 = a14 ^ ((~a10) & a11);
			a10 = c0;
			a11 = c1;

			c0 = a15 ^ ((~a16) & a17);
			c1 = a16 ^ ((~a17) & a18);
			a17 = a17 ^ ((~a18) & a19);
			a18 = a18 ^ ((~a19) & a15);
			a19 = a19 ^ ((~a15) & a16);
			a15 = c0;
			a16 = c1;

			c0 = a20 ^ ((~a21) & a22);
			c1 = a21 ^ ((~a22) & a23);
			a22 = a22 ^ ((~a23) & a24);
			a23 = a23 ^ ((~a24) & a20);
			a24 = a24 ^ ((~a20) & a21);
			a20 = c0;
			a21 = c1;

			//iota
			a_0 ^= rc[i];

			i++;
		} while (i < 24);

		a[ 0] = a_0; a[ 1] = a_1; a[ 2] = a_2; a[ 3] = a_3; a[ 4] = a_4;
		a[ 5] = a_5; a[ 6] = a_6; a[ 7] = a_7; a[ 8] = a_8; a[ 9] = a_9;
		a[10] = a10; a[11] = a11; a[12] = a12; a[13] = a13; a[14] = a14;
		a[15] = a15; a[16] = a16; a[17] = a17; a[18] = a18; a[19] = a19;
		a[20] = a20; a[21] = a21; a[22] = a22; a[23] = a23; a[24] = a24;
		//@formatter:on
	}

	private static final long[] RC = { 0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L,
	                                   0x8000000000008009L, 0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL, 0x000000008000808BL, 0x800000000000008BL,
	                                   0x8000000000008089L, 0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL, 0x8000000080008081L,
	                                   0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L };
}