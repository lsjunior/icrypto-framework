package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import com.github.lsjunior.icrypto.ICryptoLog;

public class AttributeValueConstraints extends ASN1Object {

  private final ASN1Sequence sequence;

  public AttributeValueConstraints() {
    super();
    this.sequence = new DERSequence();
  }

  private AttributeValueConstraints(final ASN1Sequence sequence) {
    super();
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (int i = 0; i < sequence.size(); i++) {
      vector.add(AttributeTypeAndValue.getInstance(sequence.getObjectAt(i)));
    }
    this.sequence = new DERSequence(vector);
  }

  public int size() {
    return this.sequence.size();
  }

  public AttributeTypeAndValue getObjectAt(final int index) {
    AttributeTypeAndValue cr = (AttributeTypeAndValue) this.sequence.getObjectAt(index);
    return cr;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static AttributeValueConstraints getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AttributeValueConstraints)) {
      return (AttributeValueConstraints) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new AttributeValueConstraints((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AttributeValueConstraints.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
