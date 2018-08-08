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
/*
 * GMP function documentation licensed under GNU Free Documentation License.
 * http://gmplib.org/manual/GNU-Free-Documentation-License.html
 *
 * Copyright 1991, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005,
 * 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013 Free Software Foundation, Inc.
 */
package org.squareup.jnagmp;

import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import java.io.File;

public final class LibGmp {

  private static final Class SIZE_T_CLASS;

  static {
    if (Native.SIZE_T_SIZE == 4) {
      SIZE_T_CLASS = SizeT4.class;
    } else if (Native.SIZE_T_SIZE == 8) {
      SIZE_T_CLASS = SizeT8.class;
    } else {
      throw new AssertionError("Unexpected Native.SIZE_T_SIZE: " + Native.SIZE_T_SIZE);
    }
  }

  static {
    loadLibGmp();
  }

  public static void loadLibGmp() {
    try {
      // Explicitly try to load the embedded version first.
      File file = Native.extractFromResourcePath("gmp", LibGmp.class.getClassLoader());
      load(file.getAbsolutePath());
      return;
    } catch (Exception ignored) {
    } catch (UnsatisfiedLinkError ignored) {
    }
    // Fall back to system-wide search.
    load("gmp");
  }

  public static void load(String name) {
    NativeLibrary library = NativeLibrary.getInstance(name, LibGmp.class.getClassLoader());
    Native.register(LibGmp.class, library);
    Native.register(SIZE_T_CLASS, library);
  }

  public static final String __gmp_version;
  // CHECKSTYLE.ON: ConstantName

  static {
    __gmp_version = NativeLibrary.getProcess() // library is already loaded and linked.
        .getGlobalVariableAddress("__gmp_version") // &(const char* __gmp_version)
        .getPointer(0) // const char* __gmp_version
        .getString(0);
  }

  /** Dummy method to force class initialization. */
  public static void init() {
  }

  /** Helper method to read the value of a (size_t*), depends on {@code sizeof(size_t)}. */
  public static int readSizeT(Pointer ptr) {
    // TODO(scottb): make not public.
    if (SIZE_T_CLASS == SizeT4.class) {
      int result;
      result = ptr.getInt(0);
      assert result >= 0;
      return result;
    } else {
      long result = ptr.getLong(0);
      assert result >= 0;
      assert result < Integer.MAX_VALUE;
      return (int) result;
    }
  }

  public static class mpz_t extends Pointer {
    /** The size, in bytes, of the native structure. */
    public static final int SIZE = 16;

    /**
     * Constructs an mpz_t from a native address.
     *
     * @param peer the address of a block of native memory at least {@link #SIZE} bytes large
     */
    public mpz_t(long peer) {
      super(peer);
    }

    /**
     * Constructs an mpz_t from a Pointer.
     *
     * @param from an block of native memory at least {@link #SIZE} bytes large
     */
    public mpz_t(Pointer from) {
      this(Pointer.nativeValue(from));
    }
  }
  /** Used on systems with 4-byte size_t. */
  static class SizeT4 {
    static native void __gmpz_import(mpz_t rop, int count, int order, int size, int endian,
        int nails, Pointer buffer);

    static native Pointer __gmpz_export(Pointer rop, Pointer countp, int order, int size,
        int endian, int nails, mpz_t op);
  }

  /** Used on systems with 8-byte size_t. */
  static class SizeT8 {
    static native void __gmpz_import(mpz_t rop, long count, int order, int size, int endian,
        long nails, Pointer buffer);

    static native Pointer __gmpz_export(Pointer rop, Pointer countp, int order, long size,
        int endian, long nails, mpz_t op);
  }

  public static void __gmpz_import(mpz_t rop, int count, int order, int size, int endian, int nails,
      Pointer buffer) {
    if (SIZE_T_CLASS == SizeT4.class) {
      SizeT4.__gmpz_import(rop, count, order, size, endian, nails, buffer);
    } else {
      SizeT8.__gmpz_import(rop, count, order, size, endian, nails, buffer);
    }
  }

  public static void __gmpz_export(Pointer rop, Pointer countp, int order, int size, int endian,
      int nails, mpz_t op) {
    if (SIZE_T_CLASS == SizeT4.class) {
      SizeT4.__gmpz_export(rop, countp, order, size, endian, nails, op);
    } else {
      SizeT8.__gmpz_export(rop, countp, order, size, endian, nails, op);
    }
  }

  public static native void __gmpz_init(mpz_t integer);

  public static native void __gmpz_init2(mpz_t x, NativeLong n);

  public static native void __gmpz_clear(mpz_t x);

  public static native void __gmpz_neg(mpz_t rop, mpz_t op);

  public static native void __gmpz_powm(mpz_t rop, mpz_t base, mpz_t exp, mpz_t mod);

  public static native int __gmpz_cmp_si(mpz_t op1, NativeLong op2);

  public static native void __gmpz_powm_sec(mpz_t rop, mpz_t base, mpz_t exp, mpz_t mod);

  public static native int __gmpz_invert(mpz_t rop, mpz_t op1, mpz_t op2);

  public static native int __gmpz_jacobi(mpz_t a, mpz_t p);

  public static native void __gmpz_mul(mpz_t rop, mpz_t op1, mpz_t op2);

  public static native void __gmpz_mod(mpz_t r, mpz_t n, mpz_t d);

  public static native void __gmpz_divexact(mpz_t q, mpz_t n, mpz_t d);

  public static native void __gmpz_gcd(mpz_t rop, mpz_t op1, mpz_t op2);

  private LibGmp() {
  }
}
