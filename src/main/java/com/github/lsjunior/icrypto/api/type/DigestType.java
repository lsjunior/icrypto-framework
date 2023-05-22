package com.github.lsjunior.icrypto.api.type;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public enum DigestType {

  /* @formatter:off */
  MD2("MD2", PKCSObjectIdentifiers.md2),
  MD5("MD5", PKCSObjectIdentifiers.md5),
  SHA1("SHA-1", OIWObjectIdentifiers.idSHA1),
  SHA256("SHA-256", NISTObjectIdentifiers.id_sha256),
  SHA384("SHA-384", NISTObjectIdentifiers.id_sha384),
  SHA512("SHA-512", NISTObjectIdentifiers.id_sha512);
  /* @formatter:on */

  private final String algorithm;

  private final ASN1ObjectIdentifier identifier;

  private DigestType(final String algorithm, final ASN1ObjectIdentifier identifier) {
    this.algorithm = algorithm;
    this.identifier = identifier;
  }

  public String getAlgorithm() {
    return this.algorithm;
  }

  public ASN1ObjectIdentifier getIdentifier() {
    return this.identifier;
  }

  @Override
  public String toString() {
    return this.getAlgorithm();
  }

  public static DigestType get(final AlgorithmIdentifier algorithmIdentifier) {
    if (algorithmIdentifier != null) {
      return DigestType.get(algorithmIdentifier.getAlgorithm());
    }
    return null;
  }

  public static DigestType get(final ASN1ObjectIdentifier asn1ObjectIdentifier) {
    if (asn1ObjectIdentifier != null) {
      for (DigestType digestType : DigestType.values()) {
        if (digestType.getIdentifier().getId().equals(asn1ObjectIdentifier.getId())) {
          return digestType;
        }
      }
    }
    return null;
  }

}
