package com.github.lsjunior.icrypto.core.signature.cms;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.List;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.google.common.io.ByteSource;

public class CadesVerificationParameters implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private CertPathProvider certPathProvider;

  private List<Certificate> chain;

  private ByteSource data;

  private ByteSource signature;

  private SignatureProfile signatureProfile;

  private SignaturePolicyProvider signaturePolicyProvider;

  public CadesVerificationParameters() {
    super();
  }

  public CertPathProvider getCertPathProvider() {
    return this.certPathProvider;
  }

  public void setCertPathProvider(final CertPathProvider certPathProvider) {
    this.certPathProvider = certPathProvider;
  }

  public List<Certificate> getChain() {
    return this.chain;
  }

  public void setChain(final List<Certificate> chain) {
    this.chain = chain;
  }

  public ByteSource getData() {
    return this.data;
  }

  public void setData(final ByteSource data) {
    this.data = data;
  }

  public ByteSource getSignature() {
    return this.signature;
  }

  public void setSignature(final ByteSource signature) {
    this.signature = signature;
  }

  public SignatureProfile getSignatureProfile() {
    return this.signatureProfile;
  }

  public void setSignatureProfile(final SignatureProfile signatureProfile) {
    this.signatureProfile = signatureProfile;
  }

  public SignaturePolicyProvider getSignaturePolicyProvider() {
    return this.signaturePolicyProvider;
  }

  public void setSignaturePolicyProvider(final SignaturePolicyProvider signaturePolicyProvider) {
    this.signaturePolicyProvider = signaturePolicyProvider;
  }

}
