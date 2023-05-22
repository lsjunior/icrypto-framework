package com.github.lsjunior.icrypto.core.digest.impl;

import java.io.OutputStream;
import java.security.MessageDigest;

public class DigesterOutputStream extends OutputStream {

  private final MessageDigest digest;

  public DigesterOutputStream(final MessageDigest digest) {
    this.digest = digest;
  }

  @Override
  public void write(final byte[] bytes, final int off, final int len) {
    this.digest.update(bytes, off, len);
  }

  @Override
  public void write(final byte[] bytes) {
    this.digest.update(bytes);
  }

  @Override
  public void write(final int b) {
    this.digest.update((byte) b);
  }

  public byte[] digest() {
    return this.digest.digest();
  }
}
