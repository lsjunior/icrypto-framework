package com.github.lsjunior.icrypto.api.type;

public enum ProviderType {

  /* @formatter:off */
  APPLE("Apple"),
  SUN("SUN"),
  SUN_EC("SunEC"),
  SUN_JSSE("SunJSSE"),
  SUN_JCE("SunJCE"),
  SUN_MSCAPI("SunMSCAPI"),
  SUN_PKCS11("SunPKCS11"),
  BOUNCY_CASTLE("BC");
  /* @formatter:on */

  private final String type;

  private ProviderType(final String type) {
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
