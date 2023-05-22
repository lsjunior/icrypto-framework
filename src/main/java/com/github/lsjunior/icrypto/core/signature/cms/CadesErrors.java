package com.github.lsjunior.icrypto.core.signature.cms;

public abstract class CadesErrors {

  // Core
  public static final int UNCAUGHT_ERROR = 0;

  public static final int SIGNED_DATA_INVALID = 1;

  public static final int SIGNATURE_EMPTY = 2;

  public static final int SIGNATURE_INVALID = 3;

  public static final int CERTIFICATE_NOT_FOUND = 4;

  public static final int CERTIFICATE_INVALID = 5;

  public static final int CERTIFICATE_HIERARCHY_INVALID = 6;

  public static final int CERTIFICATE_REVOKED = 7;

  public static final int CONTENT_TYPE_NOT_FOUND = 8;

  public static final int SIGNING_TIME_INVALID = 9;

  // CAdES
  // EPES
  public static final int POLICY_NOT_FOUND = 101;

  public static final int POLICY_INVALID = 102;

  public static final int POLICY_HASH_INVALID = 103;

  public static final int POLICY_ALGORITHM_INVALID = 104;

  // T
  public static final int SIGNATURE_TIMESTAMP_NOT_FOUND = 111;

  public static final int SIGNATURE_TIMESTAMP_INVALID = 112;

  public static final int SIGNATURE_TIMESTAMP_CERTIFICATE_NOT_FOUND = 113;

  public static final int SIGNATURE_TIMESTAMP_CERTIFICATE_INVALID = 114;

  public static final int SIGNATURE_TIMESTAMP_CERTIFICATE_MISSING_KEY_USAGE = 115;

  // C
  public static final int CERTIFICATE_REFS_NOT_FOUND = 121;

  public static final int REVOCATION_REFS_NOT_FOUND = 122;

  public static final int CERTIFICATE_REF_NOT_FOUND = 123;

  public static final int CERTIFICATE_HASH_NOT_MATCHES = 124;

  // X
  public static final int REFERENCE_TIMESTAMP_NOT_FOUND = 131;

  public static final int REFERENCE_TIMESTAMP_INVALID = 132;

  public static final int REFERENCE_TIMESTAMP_CERTIFICATE_NOT_FOUND = 133;

  public static final int REFERENCE_TIMESTAMP_CERTIFICATE_INVALID = 134;

  public static final int REFERENCE_TIMESTAMP_CERTIFICATE_MISSING_KEY_USAGE = 135;

  // XL
  public static final int CERTIFICATE_VALUES_NOT_FOUND = 141;

  public static final int REVOCATION_VALUES_NOT_FOUND = 142;

  public static final int CRL_REF_NOT_FOUND = 143;

  public static final int OCSP_REF_NOT_FOUND = 144;

  // A
  public static final int ARCHIVE_TIMESTAMP_NOT_FOUND = 151;

  public static final int ARCHIVE_TIMESTAMP_INVALID = 152;

  public static final int ARCHIVE_TIMESTAMP_CERTIFICATE_NOT_FOUND = 153;

  public static final int ARCHIVE_TIMESTAMP_CERTIFICATE_INVALID = 154;

  public static final int ARCHIVE_TIMESTAMP_CERTIFICATE_MISSING_KEY_USAGE = 155;

  protected CadesErrors() {
    //
  }

}
