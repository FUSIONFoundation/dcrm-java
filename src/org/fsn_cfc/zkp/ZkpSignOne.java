package org.fsn_cfc.zkp;

import static org.fsn_cfc.util.OtherUtil.sha256Hash;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.fsn_cfc.util.BitcoinParams;
import org.fsn_cfc.util.RandomUtil;
import org.squareup.jnagmp.Gmp;





public class ZkpSignOne {

	private BigInteger z;
	private BigInteger u1;
	private BigInteger u2;
	private BigInteger s1;
	private BigInteger s2;
	private BigInteger s3;
	private BigInteger e;
	private BigInteger v;

	public ZkpSignOne(PublicParameters params, BigInteger eta, SecureRandom rand, BigInteger r, BigInteger c1, BigInteger c2, BigInteger c3) {
		
		BigInteger N = params.paillierPubKey.getN();
		BigInteger q = BitcoinParams.q;
		BigInteger nSquared = N.multiply(N);
		BigInteger nTilde = params.nTilde;
		BigInteger h1 = params.h1;
		BigInteger h2 = params.h2;
		BigInteger g = N.add(BigInteger.ONE);

		BigInteger alpha = RandomUtil.randomFromZn(q.pow(3), rand);
		BigInteger beta = RandomUtil.randomFromZnStar(N, rand);
		BigInteger gamma = RandomUtil.randomFromZn(q.pow(3).multiply(nTilde), rand);
		BigInteger rho = RandomUtil.randomFromZn(q.multiply(nTilde), rand);

		
		
		z = Gmp.modPowSecure(h1,eta, nTilde).multiply(Gmp.modPowSecure(h2,rho, nTilde)).mod(nTilde);
		u1 = Gmp.modPowSecure(g,alpha, nSquared).multiply(Gmp.modPowSecure(beta,N, nSquared)).mod(nSquared);
		u2 = Gmp.modPowSecure(h1,alpha, nTilde).multiply(Gmp.modPowSecure(h2,gamma, nTilde)).mod(nTilde);
		v = Gmp.modPowSecure(c2,alpha, nSquared);
		
		

		byte[] digest = sha256Hash(c1.toByteArray(), c2.toByteArray(), c3.toByteArray(), z.toByteArray(), u1.toByteArray(), u2.toByteArray(), v.toByteArray());

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta).add(alpha);
		s2 = r.modPow(e, N).multiply(beta).mod(N);
		s3 = e.multiply(rho).add(gamma);

	}

	
	
	
	
	
	
	
	public boolean verify(PublicParameters params, ECDomainParameters CURVE, final BigInteger c1, final BigInteger c2, final BigInteger c3) {

		final BigInteger h1 = params.h1;
		final BigInteger h2 = params.h2;
		final BigInteger N = params.paillierPubKey.getN();
		final BigInteger nTilde = params.nTilde;
		final BigInteger nSquared = N.pow(2);
		final BigInteger g = N.add(BigInteger.ONE);
		
		ExecutorService executor = Executors.newCachedThreadPool();

		int numTests = 4;
		List<Callable<Boolean>> tests = new ArrayList<Callable<Boolean>>(
				numTests);
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u1.equals(Gmp.modPowSecure(g,s1, nSquared).multiply(Gmp.modPowSecure(s2,N, nSquared))
						.multiply(Gmp.modPowSecure(c3, e.negate(), nSquared)).mod(nSquared));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u2.equals(Gmp.modPowSecure(h1,s1, nTilde).multiply(Gmp.modPowSecure(h2,s3, nTilde))
						.multiply(z.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v.equals(Gmp.modPowSecure(c2,s1, nSquared)
						.multiply(Gmp.modPowSecure(c1, e.negate(), nSquared)).mod(nSquared));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				byte[] digestRecovered = sha256Hash(c1.toByteArray(), c2.toByteArray(), c3.toByteArray(), z.toByteArray(), u1.toByteArray(), u2.toByteArray(), v.toByteArray());

				if (digestRecovered == null) {
					return false;
				}

				BigInteger eRecovered = new BigInteger(1, digestRecovered);

				return eRecovered.equals(e);
			}
		});
		
		
		List<Future<Boolean>> futures = new ArrayList<Future<Boolean>>(numTests);
		
		for(Callable<Boolean> test: tests) {
			futures.add(executor.submit(test));	
		}
		
		for(Future<Boolean> future: futures) {
			try {
				if(!future.get().booleanValue()) {
					return false;
				}
			} catch (InterruptedException e) {
				e.printStackTrace();
				return false;
			} catch (ExecutionException e) {
				e.printStackTrace();
				return false;
			}
		}
	
		executor.shutdown();
		return true;
		
	}
	
	
	

}
