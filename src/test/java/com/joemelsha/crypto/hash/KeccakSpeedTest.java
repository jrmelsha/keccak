package com.joemelsha.crypto.hash;

import java.nio.*;
import java.security.*;
import java.text.*;

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
public class KeccakSpeedTest {
	/**
	 * Preferred JVM options (can be tweaked!):
	 *
	 * -server -d64 -XX:+AggressiveOpts -XX:+UnlockExperimentalVMOptions -Xverify:none -XX:+DisableExplicitGC
	 * -XX:+UseNUMA -XX:+UseConcMarkSweepGC -XX:+CMSParallelRemarkEnabled -XX:+ScavengeBeforeFullGC
	 * -XX:+UseCMSInitiatingOccupancyOnly -XX:CMSInitiatingOccupancyFraction=70 -XX:+CMSScavengeBeforeRemark
	 * -XX:+UseParNewGC -XX:MaxGCPauseMillis=20 -XX:NewRatio=3 -XX:SurvivorRatio=16 -XX:+UseFastAccessorMethods
	 * -XX:+UseFastEmptyMethods -XX:+AlwaysPreTouch -XX:CompileThreshold=10000 -XX:InlineSmallCode=16384
	 * -XX:+UseCompressedOops -XX:+UseBiasedLocking -disablesystemassertions -Xshare:off -XX:+UsePerfData
	 * -Xmx1G -Xms1G
	 */
	public static void main(String[] args) throws Throwable {
		//pre-validation!
		KeccakTest<SHA3> test = new KeccakTest<SHA3>(SHA3.class, 512, new String[] {
		                                                               				"616263", "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0",
		                                                             				"", "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26",
		                                                             				"6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e",
		                                                             				"61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", "afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185",
		                                                            				"48656c6c6f2c20776f726c6421", "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af"
		                                                            			});
		test.init();
		test.testValid();

		System.out.println("VALID");


		int payloadSize = 100 * 1024 * 1024; // input data size
		boolean nativeMemory = true; //whether or not to use native memory buffers
		Keccak hash = new SHA3(512); //Keccak, SHA3, or SHAKE
		int digestSize = hash.digestSizeBits; //if you are using SHAKE, you could set this to anything.
		long randomSeed = 13636363L; //the input data seed

		Thread.currentThread().setPriority(Thread.MAX_PRIORITY); //reduce random spikes

		byte[] in = new byte[payloadSize];
		ByteBuffer inBuffer = nativeMemory ? ByteBuffer.allocateDirect(payloadSize) : ByteBuffer.wrap(in);
		ByteBuffer outBuffer = nativeMemory ? ByteBuffer.allocateDirect(digestSize) : ByteBuffer.allocate(digestSize);
		SecureRandom gen = new SecureRandom();

		long totalBytes = 0L,
			 totalElapse = 0L;
		while (true) {
			gen.setSeed(randomSeed);
			gen.nextBytes(in);
			inBuffer.clear();
			if (nativeMemory)
				inBuffer.put(in, 0, payloadSize);
			else
				inBuffer.position(payloadSize);
			inBuffer.flip();
			long bytes = inBuffer.remaining();

			outBuffer.clear();
			outBuffer.limit(digestSize);

			hash.reset();

			long begin = System.nanoTime();
			hash.update(inBuffer);
			hash.digest(outBuffer);
			long end = System.nanoTime();
			long elapse = end - begin;

			outBuffer.flip(); //could test your buffer here to an existing source?

			totalBytes += bytes;
			totalElapse += elapse;

			System.out.println(payloadSize + " (rand=" + gen.getAlgorithm() + "[seed=" + randomSeed + "]" + ")" + " => " + hash.toString() + " (native=" + nativeMemory + ")" + " => " + digestSize  + "  \t  " + "cur: " + toString(bytes, elapse) + "  \t  " + "avg: " + toString(totalBytes, totalElapse));
		}
	}

	private static String toString(long bytes, long elapseNS) {
		double elapseS = elapseNS / (1000000.0 * 1000.0);
		double bytesM = bytes / (1024.0 * 1024.0);
		double mbs = bytesM / elapseS;
		return NumberFormat.getNumberInstance().format(mbs) + " MB/s";
	}
}
