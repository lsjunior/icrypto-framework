package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class CertificateTrustTrees extends ASN1Object {

  private final ASN1Sequence sequence;

  public CertificateTrustTrees() {
    super();
    this.sequence = new DERSequence();
  }

  private CertificateTrustTrees(final ASN1Sequence sequence) {
    super();
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (int i = 0; i < sequence.size(); i++) {
      vector.add(CertificateTrustPoint.getInstance(sequence.getObjectAt(i)));
    }
    this.sequence = new DERSequence(vector);
  }

  public int size() {
    return this.sequence.size();
  }

  public CertificateTrustPoint getObjectAt(final int index) {
    CertificateTrustPoint ctp = (CertificateTrustPoint) this.sequence.getObjectAt(index);
    return ctp;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static CertificateTrustTrees getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof CertificateTrustTrees)) {
      return (CertificateTrustTrees) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new CertificateTrustTrees((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return CertificateTrustTrees.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
