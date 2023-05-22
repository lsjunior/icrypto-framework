package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.x509.KeyPurposeId;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.ExtendedKeyUsageType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;

public class X509CertificateKeyUsage implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private boolean[] keyUsage;

  private List<String> extendedKeyUsage;

  X509CertificateKeyUsage(final X509Certificate certificate) {
    super();
    if (certificate != null) {
      try {
        this.init(certificate.getKeyUsage(), certificate.getExtendedKeyUsage());
      } catch (CertificateParsingException e) {
        throw new ICryptoException(e);
      }
    } else {
      this.init(null, null);
    }
  }

  X509CertificateKeyUsage(final boolean[] keyUsage, final List<String> extendedKeyUsage) {
    super();
    this.init(keyUsage, extendedKeyUsage);
  }

  private void init(final boolean[] keyUsage, final List<String> extendedKeyUsage) {
    this.keyUsage = keyUsage;
    this.extendedKeyUsage = extendedKeyUsage;

    if (this.keyUsage == null) {
      this.keyUsage = new boolean[9];
    }

    if (this.extendedKeyUsage == null) {
      this.extendedKeyUsage = Collections.emptyList();
    }
  }

  // Key Usage
  public boolean isKeyUsageCrlSign() {
    return this.getKeyUsage(KeyUsageType.CRL_SIGN.getIndex());
  }

  public boolean isKeyUsageDataEncipherment() {
    return this.getKeyUsage(KeyUsageType.DATA_ENCIPHERMENT.getIndex());
  }

  public boolean isKeyUsageDecipherOnly() {
    return this.getKeyUsage(KeyUsageType.DECIPHER_ONLY.getIndex());
  }

  public boolean isKeyUsageDigitalSignature() {
    return this.getKeyUsage(KeyUsageType.DIGITAL_SIGNATURE.getIndex());
  }

  public boolean isKeyUsageEncipherOnly() {
    return this.getKeyUsage(KeyUsageType.ENCIPHER_ONLY.getIndex());
  }

  public boolean isKeyUsageKeyAgreement() {
    return this.getKeyUsage(KeyUsageType.KEY_AGREEMENT.getIndex());
  }

  public boolean isKeyUsageKeyCertSign() {
    return this.getKeyUsage(KeyUsageType.KEY_CERT_SIGN.getIndex());
  }

  public boolean isKeyUsageKeyEncipherment() {
    return this.getKeyUsage(KeyUsageType.KEY_ENCIPHERMENT.getIndex());
  }

  public boolean isKeyUsageNonRepudiation() {
    return this.getKeyUsage(KeyUsageType.NON_REPUDIATION.getIndex());
  }

  private boolean getKeyUsage(final int index) {
    if (this.keyUsage == null) {
      return false;
    }
    return this.keyUsage[index];
  }

  // Extended Key Usage
  public boolean isExtendedKeyUsageAny() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.ANY.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageClientAuth() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.CLIENT_AUTH.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageCodeSign() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.CODE_SIGN.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageEmailProtection() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.EMAIL_PROTECTION.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageOcspSigning() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.OCSP_SIGNING.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageServerAuth() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.SERVER_AUTH.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageSmartCardLogin() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.SMART_CARD_LOGIN.getKeyPurposeId());
  }

  public boolean isExtendedKeyUsageTimestamping() {
    return this.getExtendedKeyUsage(ExtendedKeyUsageType.TIMESTAMPING.getKeyPurposeId());
  }

  private boolean getExtendedKeyUsage(final KeyPurposeId id) {
    if (this.extendedKeyUsage == null) {
      return false;
    }
    String oid = id.getId();
    if (this.extendedKeyUsage.contains(oid)) {
      return true;
    }
    return false;
  }

  // Instance
  public static X509CertificateKeyUsage getInstance(final Certificate certificate) {
    return new X509CertificateKeyUsage((X509Certificate) certificate);
  }

  public static X509CertificateKeyUsage getInstance(final X509Certificate certificate) {
    return new X509CertificateKeyUsage(certificate);
  }

  public static X509CertificateKeyUsage getInstance(final boolean[] keyUsage, final List<String> extendedKeyUsage) {
    return new X509CertificateKeyUsage(keyUsage, extendedKeyUsage);
  }

}
