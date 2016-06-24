package com.joemelsha.crypto.hash;

import java.nio.*;
import java.security.*;
import java.text.*;

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
		int payloadSize = 100 * 1024 * 1024; // input data size
		boolean nativeMemory = true; //whether or not to use native memory buffers
		Keccak hash = new SHA3(512); //Keccak, SHA3, or SHAKE
		int digestSize = hash.getDigestSize(); //if you are using SHAKE, you could set this to anything.
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

			System.out.println("cur: " + toString(bytes, elapse) + "  \t  " + "avg: " + toString(totalBytes, totalElapse));
		}
	}

	private static String toString(long bytes, long elapseNS) {
		double elapseS = elapseNS / (1000000.0 * 1000.0);
		double bytesM = bytes / (1024.0 * 1024.0);
		double mbs = bytesM / elapseS;
		return NumberFormat.getNumberInstance().format(mbs) + " MB/s";
	}
}
