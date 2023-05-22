package com.github.lsjunior.icrypto.core.crypt.impl;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.KeyType;
import com.github.lsjunior.icrypto.core.crypt.Crypter;
import com.github.lsjunior.icrypto.core.crypt.impl.CrypterExecutor.Mode;
import com.google.common.base.Strings;

public class SynchronousCrypter implements Crypter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private SecretKey key;

  private KeyType keyType;

  public SynchronousCrypter(final SecretKey key) {
    super();
    this.key = key;
    this.keyType = KeyType.get(this.key.getAlgorithm());
  }

  public SynchronousCrypter(final KeyType type) {
    this(type, null);
  }

  public SynchronousCrypter(final KeyType type, final String seed) {
    super();
    try {
      KeyGenerator generator = KeyGenerator.getInstance(type.getAlgorithm());

      if (!Strings.isNullOrEmpty(seed)) {
        SecureRandom random = new SecureRandom(seed.getBytes());
        generator.init(random);
      }

      this.keyType = type;
      this.key = generator.generateKey();
    } catch (GeneralSecurityException e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public byte[] encrypt(final byte[] data) {
    return this.encrypt(data, null);
  }

  @Override
  public byte[] encrypt(final byte[] data, final String seed) {
    try {
      CrypterExecutor operation = new CrypterExecutor(this.key, Mode.ENCRYPT, data, seed);
      return operation.execute();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public byte[] decrypt(final byte[] data) {
    return this.decrypt(data, null);
  }

  @Override
  public byte[] decrypt(final byte[] data, final String seed) {
    try {
      CrypterExecutor operation = new CrypterExecutor(this.key, Mode.DECRYPT, data, seed);
      return operation.execute();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public String getAlgorithm() {
    if (this.keyType == null) {
      return null;
    }
    return this.keyType.getAlgorithm();
  }

}
