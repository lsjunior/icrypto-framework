package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.GeneralNames;

import com.github.lsjunior.icrypto.ICryptoLog;

public class PolicyIssuerName extends ASN1Object {

  private final GeneralNames names;

  public PolicyIssuerName(final GeneralNames names) {
    super();
    this.names = names;
  }

  public GeneralNames getValue() {
    return this.names;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.names.toASN1Primitive();
  }

  @Override
  public String toString() {
    return this.names.toString();
  }

  public static PolicyIssuerName getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof PolicyIssuerName)) {
      return (PolicyIssuerName) obj;
    }
    if (obj instanceof GeneralNames) {
      return new PolicyIssuerName((GeneralNames) obj);
    }
    if (obj instanceof ASN1Sequence) {
      return new PolicyIssuerName(GeneralNames.getInstance(obj));
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return PolicyIssuerName.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
