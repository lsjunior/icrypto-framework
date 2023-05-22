package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class PolicyInfos extends ASN1Object {

  private final DERSequence sequence;

  public PolicyInfos(final DERSequence sequence) {
    super();
    this.sequence = sequence;
  }

  public int size() {
    return this.sequence.size();
  }

  public PolicyInfo getPolicyAt(final int index) {
    PolicyInfo policy = (PolicyInfo) this.sequence.getObjectAt(index);
    return policy;
  }

  public PolicyInfo getPolicyById(final String id) {
    for (int i = 0; i < this.sequence.size(); i++) {
      PolicyInfo info = this.getPolicyAt(i);
      String policyOid = info.getPolicyId().getId();
      if (id.equals(policyOid)) {
        return info;
      }
    }
    return null;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static PolicyInfos getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof PolicyInfos)) {
      return (PolicyInfos) obj;
    }
    if (obj instanceof ASN1Sequence) {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      ASN1Sequence as = (ASN1Sequence) obj;
      for (int i = 0; i < as.size(); i++) {
        vector.add(PolicyInfo.getInstance(as.getObjectAt(i)));
      }
      DERSequence sequence = new DERSequence(vector);
      return new PolicyInfos(sequence);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return PolicyInfos.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
