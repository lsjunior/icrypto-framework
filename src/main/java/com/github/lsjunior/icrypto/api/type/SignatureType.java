package com.github.lsjunior.icrypto.api.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import com.google.common.base.Strings;

public enum SignatureType {

  /* @formatter:off */
  MD2_RSA("MD2withRSA", PKCSObjectIdentifiers.md2WithRSAEncryption, KeyPairType.RSA, DigestType.MD2), /**/
  MD5_RSA("MD5withRSA", PKCSObjectIdentifiers.md5WithRSAEncryption, KeyPairType.RSA, DigestType.MD5), /**/
  SHA1_RSA("SHA1withRSA", PKCSObjectIdentifiers.sha1WithRSAEncryption, KeyPairType.RSA, DigestType.SHA1), /**/
  SHA256_RSA("SHA256withRSA", PKCSObjectIdentifiers.sha256WithRSAEncryption, KeyPairType.RSA, DigestType.SHA256), /**/
  SHA384_RSA("SHA384withRSA", PKCSObjectIdentifiers.sha384WithRSAEncryption, KeyPairType.RSA, DigestType.SHA384), /**/
  SHA512_RSA("SHA512withRSA", PKCSObjectIdentifiers.sha512WithRSAEncryption, KeyPairType.RSA, DigestType.SHA512), /**/
  SHA1_DSA("SHA1withDSA", X9ObjectIdentifiers.id_dsa_with_sha1, KeyPairType.DSA, DigestType.SHA1), /**/
  SHA1_ECDSA("SHA1withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA1, KeyPairType.EC, DigestType.SHA1), /**/
  SHA256_ECDSA("SHA256withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA256, KeyPairType.EC, DigestType.SHA256), /**/
  SHA384_ECDSA("SHA384withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA384, KeyPairType.EC, DigestType.SHA384), /**/
  SHA512_ECDSA("SHA512withECDSA", X9ObjectIdentifiers.ecdsa_with_SHA512, KeyPairType.EC, DigestType.SHA512);
  /* @formatter:on */

  private final String algorithm;

  private final ASN1ObjectIdentifier identifier;

  private final KeyPairType keyPairType;

  private final DigestType digestType;

  private SignatureType(final String algorithm, final ASN1ObjectIdentifier identifier, final KeyPairType keyPairType, final DigestType digestType) {
    this.algorithm = algorithm;
    this.identifier = identifier;
    this.keyPairType = keyPairType;
    this.digestType = digestType;
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public ASN1ObjectIdentifier getIdentifier() {
    return this.identifier;
  }

  public KeyPairType getKeyPairType() {
    return this.keyPairType;
  }

  public DigestType getDigestType() {
    return this.digestType;
  }

  @Override
  public String toString() {
    return this.getAlgorithm();
  }

  public static SignatureType get(final AlgorithmIdentifier algorithmIdentifier) {
    if (algorithmIdentifier != null) {
      return SignatureType.get(algorithmIdentifier.getAlgorithm());
    }
    return null;
  }

  public static SignatureType get(final ASN1ObjectIdentifier asn1ObjectIdentifier) {
    if (asn1ObjectIdentifier != null) {
      for (SignatureType st : SignatureType.values()) {
        if (st.getIdentifier().getId().equals(asn1ObjectIdentifier.getId())) {
          return st;
        }
      }
    }
    return null;
  }

  public static SignatureType get(final String algorithm) {
    if (Strings.isNullOrEmpty(algorithm)) {
      return null;
    }
    for (SignatureType st : SignatureType.values()) {
      if (st.getAlgorithm().equalsIgnoreCase(algorithm)) {
        return st;
      }
    }
    return null;
  }

}
