package com.github.lsjunior.icrypto.core.crypt.impl;

import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.KeyPairType;
import com.github.lsjunior.icrypto.core.crypt.Crypter;
import com.github.lsjunior.icrypto.core.crypt.impl.CrypterExecutor.Mode;
import com.google.common.base.Strings;

public class AsynchronousCrypter implements Crypter, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final int DEFAULT_KEY_SIZE = 1024;

  private KeyPair keyPair;

  private KeyPairType keyPairType;

  public AsynchronousCrypter(final KeyPair keyPair) {
    super();
    this.keyPair = keyPair;
    for (KeyPairType keyPairType : KeyPairType.values()) {
      Key key = null;
      if (this.keyPair.getPrivate() != null) {
        key = this.keyPair.getPrivate();
      } else if (this.keyPair.getPublic() != null) {
        key = this.keyPair.getPublic();
      }

      if ((key != null) && (keyPairType.getAlgorithm().equals(key.getAlgorithm()))) {
        this.keyPairType = keyPairType;
        break;
      }
    }
  }

  public AsynchronousCrypter(final KeyPairType type) {
    this(type, null);
  }

  public AsynchronousCrypter(final KeyPairType type, final String seed) {
    super();
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(type.getAlgorithm());

      if (!Strings.isNullOrEmpty(seed)) {
        SecureRandom random = new SecureRandom(seed.getBytes());
        generator.initialize(AsynchronousCrypter.DEFAULT_KEY_SIZE, random);
      }

      this.keyPairType = type;
      this.keyPair = generator.generateKeyPair();
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
    PrivateKey privateKey = this.keyPair.getPrivate();
    if (privateKey == null) {
      throw new IllegalStateException("Private key is null");
    }
    try {
      CrypterExecutor operation = new CrypterExecutor(privateKey, Mode.ENCRYPT, data, seed);
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
    PublicKey publicKey = this.keyPair.getPublic();
    if (publicKey == null) {
      throw new IllegalStateException("Public key is null");
    }
    try {
      CrypterExecutor operation = new CrypterExecutor(publicKey, Mode.DECRYPT, data, seed);
      return operation.execute();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public String getAlgorithm() {
    if (this.keyPairType == null) {
      return null;
    }
    return this.keyPairType.getAlgorithm();
  }

}
