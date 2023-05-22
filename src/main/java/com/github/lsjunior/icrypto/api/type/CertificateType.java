package com.github.lsjunior.icrypto.api.type;

public enum CertificateType {

  X509("X.509");

  private final String type;

  private CertificateType(final String type) {
    this.type = type;
  }

  public String getType() {
    return this.type;
  }

  @Override
  public String toString() {
    return this.getType();
  }

  public static CertificateType get(final String type) {
    for (CertificateType certificateType : CertificateType.values()) {
      if (certificateType.getType().equalsIgnoreCase(type)) {
        return certificateType;
      }
    }
    return null;
  }

}
