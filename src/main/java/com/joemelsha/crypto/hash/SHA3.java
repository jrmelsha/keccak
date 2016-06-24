package com.joemelsha.crypto.hash;

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
public class SHA3 extends Keccak {
	public SHA3(int digestSizeBits) {
		super(digestSizeBits);
	}

	public SHA3(SHA3 other) {
		super(other);
	}

	@Override
	public String toString() {
		return "SHA3-" + digestSizeBits;
	}

	@Override
	protected void pad() {
		updateBits(0x02, 2);
		super.pad();
	}

	@Override
	protected void squeeze() {
		throw new UnsupportedOperationException("SHA-3 cannot be squeezed");
	}

	@Override
	protected int stateSizeFor(int digestSizeBits) {
		//@formatter:off
		switch (digestSizeBits) {
			case 224: return 1152;
			case 256: return 1088;
			case 384: return  832;
			case 512: return  576;
			default: throw new IllegalArgumentException("Invalid digestSizeBits: " + digestSizeBits + " ⊄ { 224, 256, 384, 512 }");
		}
		//@formatter:on
	}
}