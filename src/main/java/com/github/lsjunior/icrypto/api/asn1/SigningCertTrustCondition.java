package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SigningCertTrustCondition extends ASN1Object {

  private final CertificateTrustTrees signerTrustTrees;

  private final CertRevReq signerRevReq;

  private SigningCertTrustCondition(final ASN1Sequence sequence) {
    super();
    this.signerTrustTrees = CertificateTrustTrees.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.signerRevReq = CertRevReq.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public SigningCertTrustCondition(final CertificateTrustTrees signerTrustTrees, final CertRevReq signerRevReq) {
    super();
    this.signerTrustTrees = signerTrustTrees;
    this.signerRevReq = signerRevReq;
  }

  public CertificateTrustTrees getSignerTrustTrees() {
    return this.signerTrustTrees;
  }

  public CertRevReq getSignerRevReq() {
    return this.signerRevReq;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.signerTrustTrees, this.signerRevReq);
  }

  public static SigningCertTrustCondition getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SigningCertTrustCondition)) {
      return (SigningCertTrustCondition) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SigningCertTrustCondition((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SigningCertTrustCondition.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
