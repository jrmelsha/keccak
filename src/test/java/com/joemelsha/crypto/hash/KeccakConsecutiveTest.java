package com.joemelsha.crypto.hash;

import java.nio.charset.*;

import org.junit.*;

/**
 * @author Joseph Robert Melsha (joe.melsha@live.com)
 *
 * Source: https://github.com/jrmelsha/keccak
 * Created: Feb 25, 2019
 *
 * Copyright 2019 Joseph Robert Melsha
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
public class KeccakConsecutiveTest {
	public KeccakConsecutiveTest() {
	}

	@Before
	public void init() {
	}

	@Test
	public void testValid() {
		//TEST VECTORS
		final Charset ascii = Charset.forName("US-ASCII");
		final byte[] a = "abcdefghijklmnopqrstuvwxyz".getBytes(ascii);
		//System.out.println(a.length);
		final byte[] b = "ABCDEFG".getBytes(ascii);
		//System.out.println(b.length);

		final byte[] input = new byte[a.length + b.length];
		System.arraycopy(a, 0, input, 0, a.length);
		System.arraycopy(b, 0, input, a.length, b.length);

		//System.out.println(new String(input, ascii) + ", " + input.length);

		//spongycastle
		org.spongycastle.crypto.digests.KeccakDigest kd = new org.spongycastle.crypto.digests.KeccakDigest(256);

		kd.reset();
		kd.update(a, 0, a.length);
		kd.update(b, 0, b.length);
		byte[] output = new byte[32];
		kd.doFinal(output, 0);
		String b1 = toHexString(output);
		//System.out.println(b1);

		kd.reset();
		kd.update(input, 0, input.length);
		kd.doFinal(output, 0);
		String b2 = toHexString(output);
		//System.out.println(b2);

		Assert.assertEquals("spongycastle failed", b1, b2);

		//OURS
		final Keccak k = new Keccak(256);

		//ensure no error
		k.reset();
		k.update(new byte[1]);
		k.update(new byte[7]);

		k.reset();
		k.update(input);
		String k1 = toHexString(k.digest(32).array());
		//System.out.println(k1);

		k.reset();
		k.update(a);
		k.update(b);
		String k2 = toHexString(k.digest(32).array());
		//System.out.println(k2);

		Assert.assertEquals("ours failed", k1, k2);

		Assert.assertEquals("spongycastle != ours failed", k2, b2);
	}

	@After
	public void destroy() {
	}

	public static final char[] HEX_TABLE = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	public static String toHexString(byte[] b) {
		return toHexString(b, 0, b.length);
	}

	public static String toHexString(byte[] b, int off, int len) {
		char[] out = new char[len << 1];
		char[] t = HEX_TABLE;
		int i = 0;
		for (len += off; off < len; ++off) {
			int v = b[off] & 0xff;
			out[i++] = t[v >>> 4];
			out[i++] = t[v & 0xf];
		}
		return new String(out);
	}
}
