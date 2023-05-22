package com.github.lsjunior.icrypto.core.certificate;

import java.io.Serializable;

import com.github.lsjunior.icrypto.ICryptoConstants;

public class ValidationError implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private final String name;

  private final String message;

  public ValidationError(final String name, final String message) {
    super();
    this.name = name;
    this.message = message;
  }

  public String getName() {
    return this.name;
  }

  public String getMessage() {
    return this.message;
  }

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append(this.getName());
    builder.append("[");
    builder.append("ERROR:" + this.getMessage());
    builder.append("]");
    return builder.toString();
  }

}
