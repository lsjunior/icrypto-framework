package com.github.lsjunior.icrypto.api.type;

public enum CertificateVersionType {

  V1("v1"), V3("v3");

  private final String label;

  private CertificateVersionType(final String label) {
    this.label = label;
  }

  @Override
  public String toString() {
    return this.label;
  }

}
