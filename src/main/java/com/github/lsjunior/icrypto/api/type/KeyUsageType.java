package com.github.lsjunior.icrypto.api.type;

import org.bouncycastle.asn1.x509.KeyUsage;

public enum KeyUsageType {

  // @formatter:off
  CRL_SIGN("CRL Sign", 6, KeyUsage.cRLSign), /**/
  DATA_ENCIPHERMENT("Data Encipherment", 3, KeyUsage.dataEncipherment), /**/
  DECIPHER_ONLY("Decipher Only", 8, KeyUsage.decipherOnly), /**/
  DIGITAL_SIGNATURE("Digital Signature", 0, KeyUsage.digitalSignature), /**/
  ENCIPHER_ONLY("Encipher Only", 7, KeyUsage.encipherOnly), /**/
  KEY_AGREEMENT("Key Agreement", 4, KeyUsage.keyAgreement), /**/
  KEY_CERT_SIGN("Key Cert Sign", 5, KeyUsage.keyCertSign), /**/
  KEY_ENCIPHERMENT("Key Enchiperment", 2, KeyUsage.keyEncipherment), /**/
  NON_REPUDIATION("Non Repudation", 1, KeyUsage.nonRepudiation);
  // @formatter:on

  private final String label;

  private final int index;

  private final int usage;

  private KeyUsageType(final String label, final int index, final int usage) {
    this.label = label;
    this.index = index;
    this.usage = usage;
  }

  @Override
  public String toString() {
    return this.label;
  }

  public int getIndex() {
    return this.index;
  }

  public int getUsage() {
    return this.usage;
  }

  public static KeyUsageType get(final int usage) {
    for (KeyUsageType ku : KeyUsageType.values()) {
      if (ku.getUsage() == usage) {
        return ku;
      }
    }
    return null;
  }

}
