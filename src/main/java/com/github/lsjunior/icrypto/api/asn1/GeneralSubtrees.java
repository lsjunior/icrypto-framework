package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralSubtree;

import com.github.lsjunior.icrypto.ICryptoLog;

public class GeneralSubtrees extends ASN1Object {

  private final ASN1Sequence sequence;

  public GeneralSubtrees() {
    super();
    this.sequence = new DERSequence();
  }

  private GeneralSubtrees(final ASN1Sequence sequence) {
    super();
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (int i = 0; i < sequence.size(); i++) {
      vector.add(GeneralSubtree.getInstance(sequence.getObjectAt(i)));
    }
    this.sequence = new DERSequence(vector);
  }

  public int size() {
    return this.sequence.size();
  }

  public GeneralSubtree getObjectAt(final int index) {
    GeneralSubtree gs = (GeneralSubtree) this.sequence.getObjectAt(index);
    return gs;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static GeneralSubtrees getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof GeneralSubtrees)) {
      return (GeneralSubtrees) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new GeneralSubtrees((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return GeneralSubtrees.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
