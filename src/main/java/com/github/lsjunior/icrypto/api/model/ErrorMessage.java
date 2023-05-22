package com.github.lsjunior.icrypto.api.model;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class ErrorMessage implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private int code;

  private String message;

  private boolean fatal;

  public ErrorMessage(final int code, final String message, final boolean fatal) {
    super();
    this.code = code;
    this.message = message;
    this.fatal = fatal;
  }

  public int getCode() {
    return this.code;
  }

  public void setCode(final int code) {
    this.code = code;
  }

  public String getMessage() {
    return this.message;
  }

  public void setMessage(final String message) {
    this.message = message;
  }

  public boolean isFatal() {
    return this.fatal;
  }

  public void setFatal(boolean fatal) {
    this.fatal = fatal;
  }

  @Override
  public String toString() {
    return this.getMessage() + (this.fatal ? "[FATAL]" : "[WARN]");
  }

}
