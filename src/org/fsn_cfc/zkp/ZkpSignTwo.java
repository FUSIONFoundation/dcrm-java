package org.fsn_cfc.zkp;

import static org.fsn_cfc.util.OtherUtil.getBytes;
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
import org.bouncycastle.math.ec.ECPoint;
import org.fsn_cfc.util.BitcoinParams;
import org.fsn_cfc.util.RandomUtil;
import org.squareup.jnagmp.Gmp;




public class ZkpSignTwo {

	private ECPoint u1;
	private BigInteger u2;
	private BigInteger u3;
	private BigInteger z1;
	private BigInteger z2;
	private BigInteger s1;
	private BigInteger s2;
	private BigInteger t1;
	private BigInteger t2;
	private BigInteger t3;
	private BigInteger e;
	private BigInteger v1;
	private BigInteger v3;

	public ZkpSignTwo(PublicParameters params, BigInteger eta1, BigInteger eta2, SecureRandom rand, ECPoint c, BigInteger w, BigInteger u, BigInteger randomness) {

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
		BigInteger mu = RandomUtil.randomFromZnStar(N, rand);
		BigInteger theta = RandomUtil.randomFromZn(q.pow(8), rand);
		BigInteger tau = RandomUtil.randomFromZn(q.pow(8).multiply(nTilde), rand);

		BigInteger rho1 = RandomUtil.randomFromZn(q.multiply(nTilde), rand);
		BigInteger rho2 = RandomUtil.randomFromZn(q.pow(6).multiply(nTilde), rand);

		z1 = Gmp.modPowSecure(h1,eta1, nTilde).multiply(Gmp.modPowSecure(h2,rho1, nTilde))
				.mod(nTilde);
		z2 = Gmp.modPowSecure(h1,eta2, nTilde).multiply(Gmp.modPowSecure(h2,rho2, nTilde))
				.mod(nTilde);
		u1 = c.multiply(alpha);
		u2 = Gmp.modPowSecure(g,alpha, nSquared).multiply(Gmp.modPowSecure(beta,N, nSquared))
				.mod(nSquared);
		u3 = Gmp.modPowSecure(h1,alpha, nTilde).multiply(Gmp.modPowSecure(h2,gamma, nTilde))
				.mod(nTilde);
		v1 = Gmp.modPowSecure(u,alpha, nSquared)
				.multiply(Gmp.modPowSecure(g,q.multiply(theta), nSquared))
				.multiply(Gmp.modPowSecure(mu,N, nSquared)).mod(nSquared);
		v3 = Gmp.modPowSecure(h1,theta, nTilde).multiply(Gmp.modPowSecure(h2,tau, nTilde))
				.mod(nTilde);

		byte[] digest = sha256Hash(getBytes(c), w.toByteArray(), u.toByteArray(), z1.toByteArray(), z2.toByteArray(), getBytes(u1), 
				u2.toByteArray(), u3.toByteArray(), v1.toByteArray(), v3.toByteArray());

		if (digest == null) {
			throw new AssertionError();

		}

		e = new BigInteger(1, digest);

		s1 = e.multiply(eta1).add(alpha);
		s2 = e.multiply(rho1).add(gamma);
		t1 = Gmp.modPowSecure(randomness,e, N).multiply(mu).mod(N);
		t2 = e.multiply(eta2).add(theta);
		t3 = e.multiply(rho2).add(tau);
	}

	public boolean verify(PublicParameters params, ECDomainParameters CURVE, final ECPoint r, final BigInteger u, final BigInteger w) {

		final ECPoint c = params.getG(CURVE);

		final BigInteger h1 = params.h1;
		final BigInteger h2 = params.h2;
		final BigInteger N = params.paillierPubKey.getN();
		final BigInteger nTilde = params.nTilde;
		final BigInteger nSquared = N.multiply(N);
		final BigInteger g = N.add(BigInteger.ONE);
		final BigInteger q = BitcoinParams.q;
		
		
		ExecutorService executor = Executors.newCachedThreadPool();

		int numTests = 5;
		List<Callable<Boolean>> tests = new ArrayList<Callable<Boolean>>(
				numTests);
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u1.equals(c.multiply(s1).add(r.multiply(e.negate())));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return u3.equals(Gmp.modPowSecure(h1,s1, nTilde).multiply(Gmp.modPowSecure(h2,s2, nTilde))
						.multiply(z1.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v1.equals(Gmp.modPowSecure(u,s1, nSquared)
						.multiply(Gmp.modPowSecure(g,q.multiply(t2), nSquared))
						.multiply(Gmp.modPowSecure(t1,N, nSquared))
						.multiply(w.modPow(e.negate(), nSquared)).mod(nSquared));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				return v3.equals(Gmp.modPowSecure(h1,t2, nTilde).multiply(Gmp.modPowSecure(h2,t3, nTilde))
						.multiply(z2.modPow(e.negate(), nTilde)).mod(nTilde));
			}
		});
		
		tests.add(new Callable<Boolean>() {
			@Override
			public Boolean call() {
				byte[] digestRecovered = sha256Hash(getBytes(c), w.toByteArray(), u.toByteArray(), z1.toByteArray(), z2.toByteArray(), getBytes(u1),
						u2.toByteArray(), u3.toByteArray(), v1.toByteArray(), v3.toByteArray());

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
