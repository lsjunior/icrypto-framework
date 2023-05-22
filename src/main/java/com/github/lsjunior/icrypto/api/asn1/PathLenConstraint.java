package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

import com.github.lsjunior.icrypto.ICryptoLog;

public class PathLenConstraint extends ASN1Object {

  private final ASN1Integer value;

  public PathLenConstraint(final ASN1Integer value) {
    super();
    this.value = value;
  }

  public ASN1Integer getValue() {
    return this.value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.value;
  }

  @Override
  public String toString() {
    return this.value.toString();
  }

  public static PathLenConstraint getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof PathLenConstraint)) {
      return (PathLenConstraint) obj;
    }
    if (obj instanceof ASN1Integer) {
      return new PathLenConstraint((ASN1Integer) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return PathLenConstraint.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
