package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;

import com.github.lsjunior.icrypto.ICryptoLog;

public class SignPolicyHash extends ASN1Object {

  private final ASN1OctetString value;

  public SignPolicyHash(final ASN1OctetString value) {
    super();
    this.value = value;
  }

  public ASN1OctetString getValue() {
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

  public static SignPolicyHash getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignPolicyHash)) {
      return (SignPolicyHash) obj;
    }
    if (obj instanceof ASN1OctetString) {
      return new SignPolicyHash((ASN1OctetString) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignPolicyHash.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
