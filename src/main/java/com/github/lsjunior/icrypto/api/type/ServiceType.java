package com.github.lsjunior.icrypto.api.type;

public enum ServiceType {

  /* @formatter:off */
  CERTPATH_BUILDER("CertPathBuilder"),
  CERTPATH_VALIDATOR("CertPathValidator"),
  CERTSTORE("CertStore"),
  CERTIFICATE_FACTORY("CertificateFactory"),
  CIPHER("Cipher"),
  KEY_FACTORY("KeyFactory"),
  KEY_GENERATOR("KeyGenerator"),
  KEYPAIR_GENERATOR("KeyPairGenerator"),
  KEYSTORE("KeyStore"),
  MESSAGE_DIGEST("MessageDigest"),
  SECRET_KEY_FACTORY("SecretKeyFactory"),
  SECURER_RANDOM("SecureRandom"),
  SIGNATURE("Signature"),
  TRUSTMANAGER_FACTORY("TrustManagerFactory"),
  XMLSIGNATURE_FACTORY("XMLSignatureFactory");
  /* @formatter:om */

  private String type;

  private ServiceType(final String type) {
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
