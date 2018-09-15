package com.joemelsha.crypto.hash;

/**
 * @author Joseph Robert Melsha (joe.melsha@live.com)
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
public class SHAKE extends Keccak {
	public SHAKE(int digestSizeBits) {
		super(digestSizeBits);
	}

	public SHAKE(SHAKE other) {
		super(other);
	}

	@Override
	public String toString() {
		return "SHAKE" + digestSizeBits;
	}

	@Override
	protected void pad() {
		updateBits(0x0f, 4);
		super.pad();
	}

	@Override
	protected int rateSizeBitsFor(int digestSizeBits) {
		//@formatter:off
		switch (digestSizeBits) {
			case 128: return 1344;
			case 256: return 1088;
			default: throw new IllegalArgumentException("Invalid digestSizeBits: " + digestSizeBits + " ⊄ { 128, 256 }");
		}
		//@formatter:on
	}
}