package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class AttributeTrustCondition extends ASN1Object {

  private final ASN1Boolean attributeMandated;

  private final HowCertAttribute howCertAttribute;

  private CertificateTrustTrees attrCertificateTrustTrees;

  private CertRevReq attrRevReq;

  private AttributeConstraints attributeConstraints;

  private AttributeTrustCondition(final ASN1Sequence sequence) {
    super();
    this.attributeMandated = ASN1Boolean.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.howCertAttribute = HowCertAttribute.getInstance(Asn1Objects.getObjectAt(sequence, 1));
    if (sequence.size() > 2) {
      for (int i = 2; i < sequence.size(); i++) {
        ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
        int tagNo = taggedObject.getTagNo();
        Object obj = taggedObject.toASN1Primitive();
        switch (tagNo) {
          case 0:
            this.attrCertificateTrustTrees = CertificateTrustTrees.getInstance(obj);
            break;
          case 1:
            this.attrRevReq = CertRevReq.getInstance(obj);
            break;
          case 2:
            this.attributeConstraints = AttributeConstraints.getInstance(obj);
            break;
          default:
            throw new IllegalStateException("Unsupported tagNo " + tagNo);
        }
      }
    }
  }

  public AttributeTrustCondition(final ASN1Boolean attributeMandated, final HowCertAttribute howCertAttribute,
      final CertificateTrustTrees attrCertificateTrustTrees, final CertRevReq attrRevReq, final AttributeConstraints attributeConstraints) {
    super();
    this.attributeMandated = attributeMandated;
    this.howCertAttribute = howCertAttribute;
    this.attrCertificateTrustTrees = attrCertificateTrustTrees;
    this.attrRevReq = attrRevReq;
    this.attributeConstraints = attributeConstraints;
  }

  public ASN1Boolean getAttributeMandated() {
    return this.attributeMandated;
  }

  public HowCertAttribute getHowCertAttribute() {
    return this.howCertAttribute;
  }

  public CertificateTrustTrees getAttrCertificateTrustTrees() {
    return this.attrCertificateTrustTrees;
  }

  public CertRevReq getAttrRevReq() {
    return this.attrRevReq;
  }

  public AttributeConstraints getAttributeConstraints() {
    return this.attributeConstraints;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.attributeMandated, this.howCertAttribute, this.attrCertificateTrustTrees, this.attrRevReq,
        this.attributeConstraints);
  }

  public static AttributeTrustCondition getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AttributeTrustCondition)) {
      return (AttributeTrustCondition) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new AttributeTrustCondition((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AttributeTrustCondition.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
