package com.github.lsjunior.icrypto;

public class ICryptoException extends RuntimeException {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public ICryptoException(final Throwable cause) {
    super(cause);
  }

  public ICryptoException(final String message) {
    super(message);
  }

  public ICryptoException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
