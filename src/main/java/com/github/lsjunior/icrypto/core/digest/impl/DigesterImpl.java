package com.github.lsjunior.icrypto.core.digest.impl;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.core.digest.Digester;
import com.google.common.io.ByteSource;

public class DigesterImpl implements Digester, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final DigestType type;

  public DigesterImpl(final DigestType type) {
    super();
    this.type = type;
  }

  @Override
  public String getAlgorithm() {
    return this.type.getAlgorithm();
  }

  @Override
  public DigestType getType() {
    return this.type;
  }

  @Override
  public byte[] digest(final byte[] data) {
    if (data == null) {
      return null;
    }
    return this.digest(ByteSource.wrap(data));
  }

  @Override
  public byte[] digest(final String data) {
    if (data == null) {
      return null;
    }
    return this.digest(ByteSource.wrap(data.getBytes()));
  }

  @Override
  public byte[] digest(final ByteSource source) {
    if (source == null) {
      return null;
    }
    try {
      MessageDigest digest = MessageDigest.getInstance(this.type.getAlgorithm());
      DigesterOutputStream outputStream = new DigesterOutputStream(digest);
      source.copyTo(outputStream);
      byte[] digested = outputStream.digest();
      return digested;
    } catch (NoSuchAlgorithmException | IOException e) {
      throw new ICryptoException(e);
    }
  }
}
