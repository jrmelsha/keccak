package com.joemelsha.crypto.hash;

import java.nio.*;
import java.nio.charset.*;

import com.sun.org.apache.xerces.internal.impl.dv.util.*;

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
	public static void main(String[] args0) {

		final Keccak k = new Keccak(256);

		final Charset ascii = Charset.forName("US-ASCII");
		final byte[] a = "abcdefghijklmnopqrstuvwxyz".getBytes(ascii);
		System.out.println(a.length);
		final byte[] b = "ABCDEFG".getBytes(ascii);
		System.out.println(b.length);

		final byte[] input = new byte[a.length + b.length];
		System.arraycopy(a, 0, input, 0, a.length);
		System.arraycopy(b, 0, input, a.length, b.length);

		System.out.println(new String(input, ascii) + ", " + input.length);

		k.update(input);
		print(k);
		k.reset();

		k.update(a);
		k.update(b);
		print(k);
		k.reset();

		org.spongycastle.crypto.digests.KeccakDigest kd = new org.spongycastle.crypto.digests.KeccakDigest(256);

		kd.update(a, 0, a.length);
		kd.update(b, 0, b.length);
		byte[] output = new byte[32];
		kd.doFinal(output, 0);
		System.out.println(HexBin.encode(output));

		kd.update(input, 0, input.length);
		kd.doFinal(output, 0);
		System.out.println(HexBin.encode(output));
	}

    private static void print(Keccak k) {
        ByteBuffer bb = k.digest(32);
        byte[] array = bb.array();
        String hex = HexBin.encode(array);
        System.out.println(hex);
    }
}
