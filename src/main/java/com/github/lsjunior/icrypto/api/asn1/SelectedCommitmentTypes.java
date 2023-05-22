package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class SelectedCommitmentTypes extends ASN1Object {

  private final ASN1Sequence sequence;

  public SelectedCommitmentTypes() {
    super();
    this.sequence = new DERSequence();
  }

  private SelectedCommitmentTypes(final ASN1Sequence sequence) {
    super();
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (int i = 0; i < sequence.size(); i++) {
      ASN1Encodable o = sequence.getObjectAt(i);
      if (o instanceof ASN1Null) {
        vector.add(ASN1Null.getInstance(sequence.getObjectAt(i)));
      } else {
        vector.add(CommitmentType.getInstance(sequence.getObjectAt(i)));
      }
    }
    this.sequence = new DERSequence(vector);
  }

  public int size() {
    return this.sequence.size();
  }

  public Object getObjectAt(final int index) {
    return this.sequence.getObjectAt(index);
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static SelectedCommitmentTypes getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SelectedCommitmentTypes)) {
      return (SelectedCommitmentTypes) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SelectedCommitmentTypes((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SelectedCommitmentTypes.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
