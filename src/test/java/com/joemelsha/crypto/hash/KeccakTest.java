package com.joemelsha.crypto.hash;

import java.lang.reflect.*;
import java.nio.*;
import java.util.*;

import org.apache.commons.codec.*;
import org.apache.commons.codec.binary.*;
import org.junit.*;
import org.junit.runner.*;
import org.junit.runners.*;
import org.junit.runners.Parameterized.*;

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
@RunWith(Parameterized.class)
public class KeccakTest<T extends Keccak> {
	@Parameters
	public static Collection<Object[]> data() {
		//@formatter:off
		return Arrays.asList(new Object[][] {
			{ SHA3.class, 512, new String[] {
   				"616263", "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0",
 				"", "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26",
 				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e",
 				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185",
				"48656c6c6f2c20776f726c6421", "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
			} },
			{ SHA3.class, 384, new String[] {
   				"616263", "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25",
 				"", "0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004",
 				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22",
 				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7",
				"48656c6c6f2c20776f726c6421", "6ba9ea268965916f5937228dde678c202f9fe756a87d8b1b7362869583a45901fd1a27289d72fc0e3ff48b1b78827d3a"
			} },
			{ SHA3.class, 256, new String[] {
  				"616263", "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532",
 				"", "a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a",
 				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376",
 				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18",
				"48656c6c6f2c20776f726c6421", "f345a219da005ebe9c1a1eaad97bbf38a10c8473e41d0af7fb617caa0c6aa722"
 			} },
			{ SHA3.class, 224, new String[] {
 				"616263", "e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf",
 				"", "6b4e03423667dbb7 3b6e15454f0eb1ab d4597f9a1b078e3f 5b5a6bc7",
 				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33",
 				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "543e6868e1666c1a 643630df77367ae5 a62a85070a51c14c bf665cbc",
				"48656c6c6f2c20776f726c6421", "6a33e22f20f16642697e8bd549ff7b759252ad56c05a1b0acc31dc69"
 			} },
			{ SHAKE.class, 256, new String[] {
  				"616263", "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4",
				"", "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e332940d8688a4e6a59aa8060f1f9bc996c05aca3c696a8b66279dc672c740bb224ec",
				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf4535423709b02843948684e029010badcc0acd8303fc85fdad3eabf4f78cae1656",
				"48656c6c6f2c20776f726c6421", "cf68a0d388047ed588ad72d3808cf9a3243f04d4901748c705fbf3a27d955542fd9d53af53e84c8abd4fce6e224af9a0a9e7eea5573a886b1af8c29f9897c8b59efe1b36ca402eec6939370dd8945963d6c81715729e6b5c937af4a8d401a07dde580df9c3b2fb1adb41bc84f68a8d75f1d123e8b7cb31df2d10677f307dbb8360ede72774429b7c58540f2e1f9705a0f7872d4ead018e2c107cd21ca9a2aa39f56974a7f01ede28572ff01eaaebf5b40232011ee6c00cc5584078601415d4500f4998644b9c35e9a604ca8651e7a06865698cb4541c89c85ce4de326b40230184f02816017b5eda27c22e42f369158c263e7de45ccb89f875006b2c2537b4c9d89d4bb9d1f64f11b925e54143d3c66e33bc2cefb890628ac5f01cb56e8569d976db9b951d8061f68dc67fbe5aacb869308c5e05d14c1120d7115eee08270d8a94b80179226e7b50555fc0c2d4412da52f9d56a74c48f3c22751db3f46ca56165319201c69d7679b52e50c14bdf5d7804515770a8bfbaf8fad9d21fd8dc7a844311ab22677ab8f94917d1932ce83dd42a29aa9eb9672fdb0cf05b6aefe0aa14ee70ad5f1262b8f4bd912b00cd73f36252ae190d0fb94b85711d8015ef52780f979778fa53fbb4d0003bf7e1fe12a0d8a68a563bbd9bd0454e964c55897e529ca1b487d1978f3efd519628b8fd8879a9339eebd5b88b4cdf9c68ae93962e026ff"
  			} },
			{ SHAKE.class, 128, new String[] {
				"616263", "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
  				"", "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
  				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5",
  				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "7b6df6ff181173b6d7898d7ff63fb07b7c237daf471a5ae5602adbccef9ccf4b",
  				"48656c6c6f2c20776f726c6421", "b5ffd113fa127f4d9c7e483cb52264ed413554ef899c0cf7c1d736ddb93313a6e76a35e24c33882d9e7c3ec4a9e0ff5fc55384da25ede64c4b721040fd87393528b765e229a3bbac54c3845cf491f8d41ad8a2ecc66d48a45212109fc78f65fee5a9288c5cc48a865efe9fe7280503b3c1964886ba4aa1b2bbb161f1827dd9b519abb2aa60881440525591f340752d7809f39e34cbe5b97df46b806ed7ea3a647c2b52d591c2afe4e6b0686029049492876059fc2d682fab82757e7fef410a2c57f1dc6929fbc8549d0a2209dd4090953a983a7d08654059cb104b23d37f7d556a94ad5f554a2ef2124f568be11acf3a1b5375818b63a61084b9a59c41ead2c59f727f7b9e047b0997954e6a42b8bca2c2a43e1033f5ec8d37cf7486ff456fbf64e0e1fedcaf303a3140144f213163a0d5248badc031882a371e0c70aef710a2df27753bcaf4b5a0b74c617343e9af54937ce679f29d188e6f718baf614ce57772e1870fcaf14122a1cbaa18cba9dbdaeced8413bf25486e4e536724b9d043735bc78d4542dd2c6b6c145f9bb82ec133cc228006eb92bee97a7c20f9cf8cbde6f4400d50f57ae1ece040d9f2bcdda21c2e10501c37168235a53687571e7a2cd13eef3c84287d0c1c18247672360dd98d9c7c5738e2905538f38466101fdf6e03863045e9205d121cb74773e1592648513a141a250464263b6cb843227cabdc8d"
			} }
		});
		//@formatter:on
	}

	public final Class<T> type;
	public final int digestSizeBits;
	public final Collection<ByteBuffer[]> testVectors = new LinkedList<ByteBuffer[]>();

	public KeccakTest(Class<T> type, int digestSizeBits, String... inputs) {
		this.type = type;
		this.digestSizeBits = digestSizeBits;
		for (int i = 0; i + 2 <= inputs.length;) {
			String input = inputs[i++].replaceAll("\\s+", "").toLowerCase();
			if (input.startsWith("0x"))
				input = input.substring(2);
			String output = inputs[i++].replaceAll("\\s+", "").toLowerCase();
			if (output.startsWith("0x"))
				output = output.substring(2);
			ByteBuffer[] tv;
			try {
				tv = new ByteBuffer[] { ByteBuffer.wrap(Hex.decodeHex(input.toCharArray())), ByteBuffer.wrap(Hex.decodeHex(output.toCharArray())) };
			} catch (DecoderException x) {
				throw new RuntimeException(x);
			}
			testVectors.add(tv);
		}
	}

	private T create() {
		try {
			return type.getConstructor(Integer.TYPE).newInstance(digestSizeBits);
		} catch (InstantiationException x) {
			throw new RuntimeException(x);
		} catch (IllegalAccessException x) {
			throw new RuntimeException(x);
		} catch (IllegalArgumentException x) {
			throw new RuntimeException(x);
		} catch (InvocationTargetException x) {
			throw new RuntimeException(x);
		} catch (NoSuchMethodException x) {
			throw new RuntimeException(x);
		} catch (SecurityException x) {
			throw new RuntimeException(x);
		}
	}

	@Before
	public void init() {
	}

	@Test
	public void testValid() {
		T hash = create();
		for (ByteBuffer[] tv : testVectors) {
			hash.reset();
			hash.update(tv[0].duplicate());
			ByteBuffer out = ByteBuffer.allocate(tv[1].remaining());
			hash.digest(out);
			out.flip();
			Assert.assertEquals("mismatch", toHexString(tv[1].duplicate()), toHexString(out.duplicate()));
		}
	}

	public static final char[] HEX_TABLE = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	private static String toHexString(ByteBuffer b) {
		int len = b.remaining(), off = b.position();
		char[] out = new char[len << 1];
		char[] t = HEX_TABLE;
		int i = 0;
		for (len += off; off < len; ++off) {
			int v = b.get(off) & 0xff;
			out[i++] = t[v >>> 4];
			out[i++] = t[v & 0xf];
		}
		return new String(out);
	}

	@After
	public void destroy() {
	}
}
