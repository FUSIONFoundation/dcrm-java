/*
 * Copyright 2013 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.squareup.jnagmp;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import java.math.BigInteger;

import org.squareup.jnagmp.LibGmp.mpz_t;

import static java.lang.Math.max;
import static java.lang.Math.min;
import static org.squareup.jnagmp.LibGmp.__gmpz_clear;
import static org.squareup.jnagmp.LibGmp.__gmpz_cmp_si;
import static org.squareup.jnagmp.LibGmp.__gmpz_divexact;
import static org.squareup.jnagmp.LibGmp.__gmpz_export;
import static org.squareup.jnagmp.LibGmp.__gmpz_gcd;
import static org.squareup.jnagmp.LibGmp.__gmpz_import;
import static org.squareup.jnagmp.LibGmp.__gmpz_init;
import static org.squareup.jnagmp.LibGmp.__gmpz_invert;
import static org.squareup.jnagmp.LibGmp.__gmpz_jacobi;
import static org.squareup.jnagmp.LibGmp.__gmpz_neg;
import static org.squareup.jnagmp.LibGmp.__gmpz_powm;
import static org.squareup.jnagmp.LibGmp.__gmpz_powm_sec;
import static org.squareup.jnagmp.LibGmp.readSizeT;

public final class Gmp {

  private static final UnsatisfiedLinkError LOAD_ERROR;

  static {
    UnsatisfiedLinkError localLoadError = null;
    try {
      LibGmp.init();
    } catch (UnsatisfiedLinkError e) {
      localLoadError = e;
    }
    LOAD_ERROR = localLoadError;
  }

  public static void checkLoaded() {
    if (LOAD_ERROR != null) {
      throw LOAD_ERROR;
    }
    BigInteger two = BigInteger.valueOf(2);
    BigInteger three = BigInteger.valueOf(3);
    BigInteger four = BigInteger.valueOf(4);
    BigInteger five = BigInteger.valueOf(5);
    BigInteger answer;

    answer = modPowInsecure(two, three, five);
    if (!three.equals(answer)) {
      throw new AssertionError("libgmp is loaded but modPowInsecure returned the wrong answer");
    }

    answer = modPowSecure(two, three, five);
    if (!three.equals(answer)) {
      throw new AssertionError("libgmp is loaded but modPowSecure returned the wrong answer");
    }

    int answr = kronecker(four, five);
    if (answr != 1) {
      throw new AssertionError("libgmp is loaded but kronecker returned the wrong answer");
    }
  }

  public static int kronecker(BigInteger a, BigInteger p) {
    return INSTANCE.get().kroneckerImpl(a, p);
  }

  public static BigInteger modPowInsecure(BigInteger base, BigInteger exponent,
      BigInteger modulus) {
    if (modulus.signum() <= 0) {
      throw new ArithmeticException("modulus must be positive");
    }
    return INSTANCE.get().modPowInsecureImpl(base, exponent, modulus);
  }

  public static BigInteger modPowSecure(BigInteger base, BigInteger exponent, BigInteger modulus) {
    if (modulus.signum() <= 0) {
      throw new ArithmeticException("modulus must be positive");
    }
    if (!modulus.testBit(0)) {
      throw new IllegalArgumentException("modulus must be odd");
    }
    return INSTANCE.get().modPowSecureImpl(base, exponent, modulus);
  }

  public static BigInteger modInverse(BigInteger val, BigInteger modulus) {
    if (modulus.signum() <= 0) {
      throw new ArithmeticException("modulus must be positive");
    }
    return INSTANCE.get().modInverseImpl(val, modulus);
  }

  public static BigInteger exactDivide(BigInteger dividend, BigInteger divisor) {
    if (divisor.signum() == 0) {
      throw new ArithmeticException("BigInteger divide by zero");
    }
    return INSTANCE.get().exactDivImpl(dividend, divisor);
  }

  public static BigInteger gcd(BigInteger value1, BigInteger value2) {
    return INSTANCE.get().gcdImpl(value1, value2);
  }

  static final ThreadLocal<Gmp> INSTANCE = new ThreadLocal<Gmp>() {
    @Override protected Gmp initialValue() {
      return new Gmp();
    }
  };

  private static final int INITIAL_BUF_BITS = 2048;
  private static final int INITIAL_BUF_SIZE = INITIAL_BUF_BITS / 8;

  private static final int MAX_OPERANDS = 4;

  private static final int SHARED_MEM_SIZE = mpz_t.SIZE * MAX_OPERANDS + Native.SIZE_T_SIZE;

  private final mpz_t[] sharedOperands = new mpz_t[MAX_OPERANDS];

  private final Pointer countPtr;

  /** A fixed, shared, reusable memory buffer. */
  private final Memory sharedMem = new Memory(SHARED_MEM_SIZE) {
    @Override protected void finalize() {
      for (mpz_t sharedOperand : sharedOperands) {
        if (sharedOperand != null) {
          __gmpz_clear(sharedOperand);
        }
      }
      super.finalize();
    }
  };

  /** Reusable scratch buffer for moving data between byte[] and mpz_t. */
  private Memory scratchBuf = new Memory(INITIAL_BUF_SIZE);

  private Gmp() {
    int offset = 0;
    for (int i = 0; i < MAX_OPERANDS; ++i) {
      this.sharedOperands[i] = new mpz_t(sharedMem.share(offset, mpz_t.SIZE));
      __gmpz_init(sharedOperands[i]);
      offset += mpz_t.SIZE;
    }
    this.countPtr = sharedMem.share(offset, Native.SIZE_T_SIZE);
    offset += Native.SIZE_T_SIZE;
    assert offset == SHARED_MEM_SIZE;
  }

  private int kroneckerImpl(BigInteger a, BigInteger p) {
    mpz_t aPeer = getPeer(a, sharedOperands[0]);
    mpz_t pPeer = getPeer(p, sharedOperands[1]);

    return __gmpz_jacobi(aPeer, pPeer);
  }

  private BigInteger modPowInsecureImpl(BigInteger base, BigInteger exp, BigInteger mod) {
    boolean invert = exp.signum() < 0;
    if (invert) {
      exp = exp.negate();
    }

    mpz_t basePeer = getPeer(base, sharedOperands[0]);
    mpz_t expPeer = getPeer(exp, sharedOperands[1]);
    mpz_t modPeer = getPeer(mod, sharedOperands[2]);

    if (invert) {
      int res = __gmpz_invert(basePeer, basePeer, modPeer);
      if (res == 0) {
        throw new ArithmeticException("val not invertible");
      }
    }

    __gmpz_powm(sharedOperands[3], basePeer, expPeer, modPeer);

    // The result size should be <= modulus size, but round up to the nearest byte.
    int requiredSize = (mod.bitLength() + 7) / 8;
    return new BigInteger(mpzSgn(sharedOperands[3]), mpzExport(sharedOperands[3], requiredSize));
  }

  private BigInteger modPowSecureImpl(BigInteger base, BigInteger exp, BigInteger mod) {
    boolean invert = exp.signum() < 0;
    if (invert) {
      exp = exp.negate();
    }

    mpz_t basePeer = getPeer(base, sharedOperands[0]);
    mpz_t expPeer = getPeer(exp, sharedOperands[1]);
    mpz_t modPeer = getPeer(mod, sharedOperands[2]);

    if (invert) {
      int res = __gmpz_invert(basePeer, basePeer, modPeer);
      if (res == 0) {
        throw new ArithmeticException("val not invertible");
      }
    }

    __gmpz_powm_sec(sharedOperands[3], basePeer, expPeer, modPeer);

    // The result size should be <= modulus size, but round up to the nearest byte.
    int requiredSize = (mod.bitLength() + 7) / 8;
    return new BigInteger(mpzSgn(sharedOperands[3]), mpzExport(sharedOperands[3], requiredSize));
  }

  private BigInteger modInverseImpl(BigInteger val, BigInteger mod) {
    mpz_t valPeer = getPeer(val, sharedOperands[0]);
    mpz_t modPeer = getPeer(mod, sharedOperands[1]);

    int res = __gmpz_invert(sharedOperands[2], valPeer, modPeer);
    if (res == 0) {
      throw new ArithmeticException("val not invertible");
    }

    // The result size should be <= modulus size, but round up to the nearest byte.
    int requiredSize = (mod.bitLength() + 7) / 8;
    return new BigInteger(mpzSgn(sharedOperands[2]), mpzExport(sharedOperands[2], requiredSize));
  }

  private BigInteger exactDivImpl(BigInteger dividend, BigInteger divisor) {
    mpz_t dividendPeer = getPeer(dividend, sharedOperands[0]);
    mpz_t divisorPeer = getPeer(divisor, sharedOperands[1]);

    __gmpz_divexact(sharedOperands[2], dividendPeer, divisorPeer);

    // The result size is never larger than the bit length of the dividend minus that of the divisor
    // plus 1 (but is at least 1 bit long to hold the case that the two values are exactly equal)
    int requiredSize = max(dividend.bitLength() - divisor.bitLength() + 1, 1);
    return new BigInteger(mpzSgn(sharedOperands[2]), mpzExport(sharedOperands[2], requiredSize));
  }

  private BigInteger gcdImpl(BigInteger value1, BigInteger value2) {
    mpz_t value1Peer = getPeer(value1, sharedOperands[0]);
    mpz_t value2Peer = getPeer(value2, sharedOperands[1]);

    __gmpz_gcd(sharedOperands[2], value1Peer, value2Peer);

    // The result size will be no larger than the smaller of the inputs
    int requiredSize = min(value1.bitLength(), value2.bitLength());
    return new BigInteger(mpzSgn(sharedOperands[2]), mpzExport(sharedOperands[2], requiredSize));
  }

  private mpz_t getPeer(BigInteger value, mpz_t sharedPeer) {
    if (value instanceof GmpInteger) {
      return ((GmpInteger) value).getPeer();
    }
    mpzImport(sharedPeer, value.signum(), value.abs().toByteArray());
    return sharedPeer;
  }

  void mpzImport(mpz_t ptr, int signum, byte[] bytes) {
    int expectedLength = bytes.length;
    ensureBufferSize(expectedLength);
    scratchBuf.write(0, bytes, 0, bytes.length);
    __gmpz_import(ptr, bytes.length, 1, 1, 1, 0, scratchBuf);
    if (signum < 0) {
      __gmpz_neg(ptr, ptr);
    }
  }

  private byte[] mpzExport(mpz_t ptr, int requiredSize) {
    ensureBufferSize(requiredSize);
    __gmpz_export(scratchBuf, countPtr, 1, 1, 1, 0, ptr);

    int count = readSizeT(countPtr);
    byte[] result = new byte[count];
    scratchBuf.read(0, result, 0, count);
    return result;
  }

  private static final NativeLong ZERO = new NativeLong();

  int mpzSgn(mpz_t ptr) {
    int result = __gmpz_cmp_si(ptr, ZERO);
    if (result < 0) {
      return -1;
    } else if (result > 0) {
      return 1;
    }
    return 0;
  }

  private void ensureBufferSize(int size) {
    if (scratchBuf.size() < size) {
      long newSize = scratchBuf.size();
      while (newSize < size) {
        newSize <<= 1;
      }
      scratchBuf = new Memory(newSize);
    }
  }
}
