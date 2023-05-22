package com.github.lsjunior.icrypto.core.crypt.impl;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.google.common.base.Strings;

class CrypterExecutor implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final Key key;

  private final Mode mode;

  private final byte[] data;

  private final String seed;

  public CrypterExecutor(final Key key, final Mode mode, final byte[] data) {
    this(key, mode, data, null);
  }

  public CrypterExecutor(final Key key, final Mode mode, final byte[] data, final String seed) {
    super();
    this.key = key;
    this.mode = mode;
    this.data = data;
    this.seed = seed;
  }

  public byte[] execute() {
    try {
      Cipher cipher = Cipher.getInstance(this.key.getAlgorithm());
      if (!Strings.isNullOrEmpty(this.seed)) {
        SecureRandom random = new SecureRandom(this.seed.getBytes());
        cipher.init(this.mode.getMode(), this.key, random);
      } else {
        cipher.init(this.mode.getMode(), this.key);
      }
      byte[] result = cipher.doFinal(this.data);
      return result;
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  public static enum Mode {
    ENCRYPT(Cipher.ENCRYPT_MODE), DECRYPT(Cipher.DECRYPT_MODE);

    private int mode;

    private Mode(final int mode) {
      this.mode = mode;
    }

    public int getMode() {
      return this.mode;
    }
  }

}
