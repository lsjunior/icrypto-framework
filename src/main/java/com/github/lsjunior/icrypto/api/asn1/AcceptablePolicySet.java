package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CertPolicyId;

import com.github.lsjunior.icrypto.ICryptoLog;

public class AcceptablePolicySet extends ASN1Object {

  private final ASN1Sequence sequence;

  public AcceptablePolicySet() {
    super();
    this.sequence = new DERSequence();
  }

  private AcceptablePolicySet(final ASN1Sequence sequence) {
    super();
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (int i = 0; i < sequence.size(); i++) {
      vector.add(CertPolicyId.getInstance(sequence.getObjectAt(i)));
    }
    this.sequence = new DERSequence(vector);
  }

  public int size() {
    return this.sequence.size();
  }

  public CertPolicyId getObjectAt(final int index) {
    CertPolicyId cpi = (CertPolicyId) this.sequence.getObjectAt(index);
    return cpi;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static AcceptablePolicySet getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AcceptablePolicySet)) {
      return (AcceptablePolicySet) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new AcceptablePolicySet((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AcceptablePolicySet.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
