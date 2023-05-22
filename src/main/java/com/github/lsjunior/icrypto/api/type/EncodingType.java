package com.github.lsjunior.icrypto.api.type;

public enum EncodingType {

  PLAIN("Plain"), BASE64("Base64"), HEX("Hex");

  private final String label;

  private EncodingType(final String label) {
    this.label = label;
  }

  @Override
  public String toString() {
    return this.label;
  }

}
