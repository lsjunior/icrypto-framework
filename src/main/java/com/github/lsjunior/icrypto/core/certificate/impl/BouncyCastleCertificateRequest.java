package com.github.lsjunior.icrypto.core.certificate.impl;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.DistinguishedName;
import com.github.lsjunior.icrypto.api.model.SubjectAlternativeName;
import com.github.lsjunior.icrypto.api.type.ExtendedKeyUsageType;
import com.github.lsjunior.icrypto.api.type.KeyPairType;
import com.github.lsjunior.icrypto.api.type.KeySizeType;
import com.github.lsjunior.icrypto.api.type.KeyUsageType;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.CertificateParameters;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.util.BcProvider;

public class BouncyCastleCertificateRequest implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final KeySizeType DEFAULT_KEY_SIZE = KeySizeType.KEYSIZE_2K;

  private static final KeyPairType DEFAULT_KEY_TYPE = KeyPairType.RSA;

  private static final SignatureType DEFAULT_SIGNATURE_TYPE = SignatureType.SHA256_RSA;

  private final long time;

  private final DistinguishedName subject;

  private KeyPair keyPair;

  private SignatureType signatureType;

  private final Identity issuer;

  private BigInteger serialNumber;

  private Date notBefore;

  private Date notAfter;

  private final String comment;

  private final String crlDistPoint;

  private final String ocspUrl;

  private final String policyUrl;

  private final boolean basicConstraintsCritical;

  private final boolean extendedKeyUsageCritical;

  private String provider;

  private final Set<KeyUsageType> keyUsage;

  private final Set<ExtendedKeyUsageType> extendedKeyUsage;

  private final Set<SubjectAlternativeName> alternativeNames;

  private final Map<String, Map<String, String>> certificatePolicies;

  public BouncyCastleCertificateRequest(final CertificateParameters request) throws NoSuchAlgorithmException {
    super();
    this.time = System.currentTimeMillis();
    this.subject = request.getSubject();
    this.keyPair = request.getKeyPair();
    this.signatureType = request.getSignatureType();
    this.issuer = request.getIssuer();
    this.serialNumber = request.getSerialNumber();
    this.notBefore = request.getNotBefore();
    this.notAfter = request.getNotAfter();
    this.comment = request.getComment();
    this.crlDistPoint = request.getCrlDistPoint();
    this.ocspUrl = request.getOcspUrl();
    this.policyUrl = request.getPolicyUrl();
    this.basicConstraintsCritical = request.isBasicConstraintsCritical();
    this.keyUsage = request.getKeyUsage();
    this.extendedKeyUsage = request.getExtendedKeyUsage();
    this.alternativeNames = request.getAlternativeNames();
    this.certificatePolicies = request.getCertificatePolicies();
    this.extendedKeyUsageCritical = request.isExtendedKeyUsageCritical();
    this.provider = request.getProvider();

    if (this.keyPair == null) {
      KeyPairType keyPairType = request.getKeyPairType();
      KeySizeType keySize = request.getKeySize();
      if (keyPairType == null) {
        keyPairType = BouncyCastleCertificateRequest.DEFAULT_KEY_TYPE;
      }
      if (keySize == null) {
        keySize = BouncyCastleCertificateRequest.DEFAULT_KEY_SIZE;
      }

      KeyPairGenerator generator = KeyPairGenerator.getInstance(keyPairType.getAlgorithm());
      generator.initialize(keySize.getSize());
      this.keyPair = generator.generateKeyPair();
    }

    if (this.signatureType == null) {
      this.signatureType = BouncyCastleCertificateRequest.DEFAULT_SIGNATURE_TYPE;
    }

    if (this.serialNumber == null) {
      this.serialNumber = BigInteger.valueOf(this.time);
    }

    if (this.notBefore == null) {
      LocalDateTime localDateTime = LocalDateTime.now().minusDays(1);
      this.notBefore = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    if (this.notAfter == null) {
      LocalDateTime localDateTime = LocalDateTime.now().plusYears(1);
      this.notAfter = Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    if (this.provider == null) {
      this.provider = BcProvider.PROVIDER_NAME;
    }
  }

  public long getTime() {
    return this.time;
  }

  public DistinguishedName getSubject() {
    return this.subject;
  }

  public KeyPair getKeyPair() {
    return this.keyPair;
  }

  public SignatureType getSignatureType() {
    return this.signatureType;
  }

  public Identity getIssuer() {
    return this.issuer;
  }

  public BigInteger getSerialNumber() {
    return this.serialNumber;
  }

  public Date getNotBefore() {
    return this.notBefore;
  }

  public Date getNotAfter() {
    return this.notAfter;
  }

  public String getComment() {
    return this.comment;
  }

  public String getCrlDistPoint() {
    return this.crlDistPoint;
  }

  public String getOcspUrl() {
    return this.ocspUrl;
  }

  public String getPolicyUrl() {
    return this.policyUrl;
  }

  public boolean isBasicConstraintsCritical() {
    return this.basicConstraintsCritical;
  }

  public boolean isExtendedKeyUsageCritical() {
    return this.extendedKeyUsageCritical;
  }

  public String getProvider() {
    return this.provider;
  }

  public Set<KeyUsageType> getKeyUsage() {
    return this.keyUsage;
  }

  public Set<ExtendedKeyUsageType> getExtendedKeyUsage() {
    return this.extendedKeyUsage;
  }

  public Set<SubjectAlternativeName> getAlternativeNames() {
    return this.alternativeNames;
  }

  public Map<String, Map<String, String>> getCertificatePolicies() {
    return this.certificatePolicies;
  }

  // Aux
  public X500Name getSubjectAsX500Name() {
    DistinguishedName name = this.getSubject();
    return Certificates.toX500Name(name);
  }

  public X500Principal getSubjectAsX500Principal() throws IOException {
    return Certificates.toX500Principal(this.getSubjectAsX500Name());
  }

  public PublicKey getPublicKey() {
    return this.getKeyPair().getPublic();
  }

  public PrivateKey getPrivateKey() {
    return this.getKeyPair().getPrivate();
  }

  public String getSignatureAlgorithm() {
    return this.getSignatureType().getAlgorithm();
  }

  public PrivateKey getIssuerPrivateKey() {
    Identity identity = this.getIssuer();
    if (identity != null) {
      return identity.getPrivateKey();
    }
    return null;
  }

  public X509Certificate getIssuerCertificate() {
    Identity identity = this.getIssuer();
    if (identity != null) {
      List<Certificate> chain = identity.getChain();
      if ((chain != null) && (!chain.isEmpty())) {
        return (X509Certificate) chain.get(0);
      }
    }
    return null;
  }

  public List<Certificate> getIssuerChain() {
    Identity identity = this.getIssuer();
    if (identity != null) {
      List<Certificate> chain = identity.getChain();
      return chain;
    }
    return null;
  }

  public boolean isCa() {
    if ((this.isBasicConstraintsCritical()) && (this.getKeyUsage().contains(KeyUsageType.KEY_CERT_SIGN))) {
      return true;
    }
    return false;
  }

}
