package com.github.lsjunior.icrypto.core.signature.jca;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

public class SignatureOutputStream extends OutputStream {

  private final Signature sig;

  SignatureOutputStream(final Signature sig) {
    this.sig = sig;
  }

  @Override
  public void write(final byte[] bytes, final int off, final int len) throws IOException {
    try {
      this.sig.update(bytes, off, len);
    } catch (SignatureException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void write(final byte[] bytes) throws IOException {
    try {
      this.sig.update(bytes);
    } catch (SignatureException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void write(final int b) throws IOException {
    try {
      this.sig.update((byte) b);
    } catch (SignatureException e) {
      throw new IllegalStateException(e);
    }
  }

  public boolean verify(final byte[] signature) throws SignatureException {
    return this.sig.verify(signature);
  }

  public byte[] sign() throws SignatureException {
    return this.sig.sign();
  }
}
