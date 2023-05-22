package com.github.lsjunior.icrypto.core.certificate;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

public class DelegateX509Certificate extends X509Certificate {

  private final X509Certificate certificate;

  public DelegateX509Certificate(final Certificate certificate) {
    this((X509Certificate) certificate);
  }

  public DelegateX509Certificate(final X509Certificate x509Certificate) {
    super();
    this.certificate = x509Certificate;
  }

  public X509Certificate getDelegate() {
    return this.certificate;
  }

  // Delegate
  @Override
  public boolean hasUnsupportedCriticalExtension() {
    return this.certificate.hasUnsupportedCriticalExtension();
  }

  @Override
  public Set<String> getCriticalExtensionOIDs() {
    return this.certificate.getCriticalExtensionOIDs();
  }

  @Override
  public boolean equals(final Object other) {
    return this.certificate.equals(other);
  }

  @Override
  public int hashCode() {
    return this.certificate.hashCode();
  }

  @Override
  public Set<String> getNonCriticalExtensionOIDs() {
    return this.certificate.getNonCriticalExtensionOIDs();
  }

  @Override
  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    this.certificate.checkValidity();
  }

  @Override
  public void checkValidity(final Date date) throws CertificateExpiredException, CertificateNotYetValidException {
    this.certificate.checkValidity(date);
  }

  @Override
  public byte[] getEncoded() throws CertificateEncodingException {
    return this.certificate.getEncoded();
  }

  @Override
  public void verify(final PublicKey key)
      throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    this.certificate.verify(key);
  }

  @Override
  public void verify(final PublicKey key, final String sigProvider)
      throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    this.certificate.verify(key, sigProvider);
  }

  @Override
  public byte[] getExtensionValue(final String oid) {
    return this.certificate.getExtensionValue(oid);
  }

  @Override
  public int getVersion() {
    return this.certificate.getVersion();
  }

  @Override
  public BigInteger getSerialNumber() {
    return this.certificate.getSerialNumber();
  }

  @Override
  public String toString() {
    return this.certificate.toString();
  }

  @Override
  public PublicKey getPublicKey() {
    return this.certificate.getPublicKey();
  }

  @Override
  public Principal getIssuerDN() {
    return this.certificate.getIssuerDN();
  }

  @Override
  public X500Principal getIssuerX500Principal() {
    return this.certificate.getIssuerX500Principal();
  }

  @Override
  public Principal getSubjectDN() {
    return this.certificate.getSubjectDN();
  }

  @Override
  public X500Principal getSubjectX500Principal() {
    return this.certificate.getSubjectX500Principal();
  }

  @Override
  public Date getNotBefore() {
    return this.certificate.getNotBefore();
  }

  @Override
  public Date getNotAfter() {
    return this.certificate.getNotAfter();
  }

  @Override
  public byte[] getTBSCertificate() throws CertificateEncodingException {
    return this.certificate.getTBSCertificate();
  }

  @Override
  public byte[] getSignature() {
    return this.certificate.getSignature();
  }

  @Override
  public String getSigAlgName() {
    return this.certificate.getSigAlgName();
  }

  @Override
  public String getSigAlgOID() {
    return this.certificate.getSigAlgOID();
  }

  @Override
  public byte[] getSigAlgParams() {
    return this.certificate.getSigAlgParams();
  }

  @Override
  public boolean[] getIssuerUniqueID() {
    return this.certificate.getIssuerUniqueID();
  }

  @Override
  public boolean[] getSubjectUniqueID() {
    return this.certificate.getSubjectUniqueID();
  }

  @Override
  public boolean[] getKeyUsage() {
    return this.certificate.getKeyUsage();
  }

  @Override
  public List<String> getExtendedKeyUsage() throws CertificateParsingException {
    return this.certificate.getExtendedKeyUsage();
  }

  @Override
  public int getBasicConstraints() {
    return this.certificate.getBasicConstraints();
  }

  @Override
  public Collection<List<?>> getSubjectAlternativeNames() throws CertificateParsingException {
    return this.certificate.getSubjectAlternativeNames();
  }

  @Override
  public Collection<List<?>> getIssuerAlternativeNames() throws CertificateParsingException {
    return this.certificate.getIssuerAlternativeNames();
  }

}
