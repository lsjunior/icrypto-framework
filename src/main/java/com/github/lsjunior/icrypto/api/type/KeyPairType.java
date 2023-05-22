package com.github.lsjunior.icrypto.api.type;

public enum KeyPairType {

  RSA("RSA", "1.2.840.113549.1.1.1"), /**/
  DSA("DSA", "1.2.840.10040.4.3"), /**/
  EC("EC", "1.2.840.10045.4.1");

  private final String algorithm;

  private final String identifier;

  private KeyPairType(final String algorithm, final String identifier) {
    this.algorithm = algorithm;
    this.identifier = identifier;
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public String getIdentifier() {
    return this.identifier;
  }

  @Override
  public String toString() {
    return this.getAlgorithm();
  }

  public static KeyPairType get(final String algorithmOrIdentifier) {
    for (KeyPairType keyPairType : KeyPairType.values()) {
      if (keyPairType.getAlgorithm().equalsIgnoreCase(algorithmOrIdentifier)) {
        return keyPairType;
      }
      if (keyPairType.getIdentifier().equalsIgnoreCase(algorithmOrIdentifier)) {
        return keyPairType;
      }
    }
    return null;
  }

}
