package com.github.lsjunior.icrypto.api.type;

public enum RevokeReasonType {

  /* @formatter:off */
  UNSPECIFIED(0, "Unspecified"),
  KEY_COMPROMISE(1, "Key Compromise"),
  CA_COMPROMISE(2, "CA Compromise"),
  AFFILIATION_CHANGED(3, "Affiliation Changed"),
  SUPER_SEDED(4, "Super Seded"),
  CESSATION_OF_OPERATION(5, "Cessation Of Operation"),
  CERTIFICATE_HOLD(6, "Certificade Hold"),
  REMOVE_FROM_CRL(8, "Remove From CRL"),
  PRIVILEGE_WITHDRAWN(9, "Privilege Withdraw"),
  AA_COMPROMISE(10, "AA Compromise");
  /* @formatter:on */

  private final int code;

  private final String label;

  private RevokeReasonType(final int code, final String label) {
    this.code = code;
    this.label = label;
  }

  public int getCode() {
    return this.code;
  }

  @Override
  public String toString() {
    return this.label;
  }

  public static RevokeReasonType get(final int code) {
    for (RevokeReasonType r : RevokeReasonType.values()) {
      if (r.getCode() == code) {
        return r;
      }
    }
    return null;
  }

}
