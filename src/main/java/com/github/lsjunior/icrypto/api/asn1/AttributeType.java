package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

import com.github.lsjunior.icrypto.ICryptoLog;

public class AttributeType extends ASN1Object {

  private final ASN1ObjectIdentifier identifier;

  public AttributeType(final ASN1ObjectIdentifier identifier) {
    super();
    this.identifier = identifier;
  }

  public ASN1ObjectIdentifier getIdentifier() {
    return this.identifier;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.identifier;
  }

  public static AttributeType getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AttributeType)) {
      return (AttributeType) obj;
    }
    if (obj instanceof ASN1ObjectIdentifier) {
      return new AttributeType((ASN1ObjectIdentifier) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AttributeType.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
