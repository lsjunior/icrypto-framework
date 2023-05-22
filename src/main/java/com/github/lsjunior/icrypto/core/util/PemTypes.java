package com.github.lsjunior.icrypto.core.util;

public abstract class PemTypes {

  // https://git.openssl.org/?p=openssl.git;a=blob;f=include/openssl/pem.h;hb=HEAD
  public static final String CERTIFICATE = "CERTIFICATE";

  public static final String CERTIFICATE_REQUEST = "CERTIFICATE REQUEST";

  public static final String CRL = "X509 CRL";

  public static final String ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";

  public static final String PKCS7 = "PKCS7";

  public static final String PRIVATE_KEY = "PRIVATE KEY";

  public static final String PRIVATE_DSA_KEY = "PRIVATE DSA KEY";

  public static final String PRIVATE_EC_KEY = "EC PRIVATE KEY";

  public static final String PRIVATE_RSA_KEY = "PRIVATE RSA KEY";

  public static final String PUBLIC_KEY = "PUBLIC KEY";

  public static final String PUBLIC_DSA_KEY = "PUBLIC DSA KEY";

  public static final String PUBLIC_ECDSA_KEY = "ECDSA PUBLIC KEY";

  public static final String PUBLIC_RSA_KEY = "PUBLIC RSA KEY";

  private PemTypes() {
    //
  }

}
