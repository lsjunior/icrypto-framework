package com.github.lsjunior.icrypto.api.type;

public enum CertPathEncodingType {

  // http://download.java.net/jdk8/docs/technotes/guides/security/StandardNames.html
  PKCS7("PKCS7"), PKIPATH("PkiPath");

  private String type;

  private CertPathEncodingType(final String type) {
    this.type = type;
  }

  public String getType() {
    return this.type;
  }

  @Override
  public String toString() {
    return this.getType();
  }

  public static CertPathEncodingType get(final String type) {
    for (CertPathEncodingType certificateType : CertPathEncodingType.values()) {
      if (certificateType.getType().equalsIgnoreCase(type)) {
        return certificateType;
      }
    }
    return null;
  }

}
