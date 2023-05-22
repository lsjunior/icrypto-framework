package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

import com.github.lsjunior.icrypto.ICryptoLog;

public class SignPolicyId extends ASN1Object {

  private final ASN1ObjectIdentifier identifier;

  public SignPolicyId(final ASN1ObjectIdentifier identifier) {
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

  @Override
  public String toString() {
    return this.identifier.getId();
  }

  public static SignPolicyId getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignPolicyId)) {
      return (SignPolicyId) obj;
    }
    if (obj instanceof ASN1ObjectIdentifier) {
      return new SignPolicyId((ASN1ObjectIdentifier) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignPolicyId.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
