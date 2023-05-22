package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class AttributeConstraints extends ASN1Object {

  private final AttributeTypeConstraints attributeTypeConstraints;

  private final AttributeValueConstraints attributeValueConstraints;

  public AttributeConstraints() {
    super();
    this.attributeTypeConstraints = new AttributeTypeConstraints();
    this.attributeValueConstraints = new AttributeValueConstraints();
  }

  private AttributeConstraints(final ASN1Sequence sequence) {
    super();
    ASN1Sequence seq0 = ASN1Sequence.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    ASN1Sequence seq1 = ASN1Sequence.getInstance(Asn1Objects.getObjectAt(sequence, 1));

    ASN1EncodableVector vector = new ASN1EncodableVector();
    if (seq0 != null) {
      for (int i = 0; i < seq0.size(); i++) {
        vector.add(ASN1ObjectIdentifier.getInstance(seq0.getObjectAt(i)));
      }
    }
    this.attributeTypeConstraints = AttributeTypeConstraints.getInstance(new DERSequence(vector));

    vector = new ASN1EncodableVector();
    if (seq1 != null) {
      for (int i = 0; i < seq1.size(); i++) {
        vector.add(AttributeTypeAndValue.getInstance(seq1.getObjectAt(i)));
      }
    }
    this.attributeValueConstraints = AttributeValueConstraints.getInstance(new DERSequence(vector));
  }

  public int size() {
    return this.attributeTypeConstraints.size();
  }

  public AttributeType getIdentifierAt(final int index) {
    AttributeType at = this.attributeTypeConstraints.getObjectAt(index);
    return at;
  }

  public AttributeTypeAndValue getValueAt(final int index) {
    AttributeTypeAndValue tav = this.attributeValueConstraints.getObjectAt(index);
    return tav;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getIdentifiers() {
    return this.attributeTypeConstraints.getObjects();
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getValues() {
    return this.attributeValueConstraints.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.attributeTypeConstraints, this.attributeValueConstraints);
  }

  public static AttributeConstraints getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AttributeConstraints)) {
      return (AttributeConstraints) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new AttributeConstraints((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AttributeConstraints.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
