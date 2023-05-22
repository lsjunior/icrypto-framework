package com.github.lsjunior.icrypto.api.type;

public enum KeyStoreType {

  /* @formatter:off */
  JKS("JKS"),
  JCEKS("JCEKS"),
  PKCS11("PKCS11"),
  PKCS12("PKCS12"),
  WINDOWS_MY("Windows-MY"),
  WINDOWS_ROOT("Windows-ROOT");
  /* @formatter:on */

  private final String type;

  private KeyStoreType(final String type) {
    this.type = type;
  }

  public String getType() {
    return this.type;
  }

  @Override
  public String toString() {
    return this.getType();
  }

}
