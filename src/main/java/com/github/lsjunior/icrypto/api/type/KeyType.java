package com.github.lsjunior.icrypto.api.type;

public enum KeyType {

  // @formatter:off
  AES("AES"),
  ARCFOUR("ARCFOUR"),
  BLOWFISH("Blowfish"),
  DES("DES"),
  DESEDE("DESede"),
  HMAC_MD5("HmacMD5"),
  HMAC_SHA1("HmacSHA1"),
  HMAC_SHA256("HmacSHA256"),
  HMAC_SHA354("HmacSHA384"),
  HMAC_SHA512("HmacSHA512");
  // @formatter:on

  private final String algorithm;

  private KeyType(final String algorithm) {
    this.algorithm = algorithm;
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  @Override
  public String toString() {
    return this.getAlgorithm();
  }

  public static KeyType get(final String algorithm) {
    for (KeyType keyType : KeyType.values()) {
      if (keyType.getAlgorithm().equalsIgnoreCase(algorithm)) {
        return keyType;
      }
    }
    return null;
  }

}
