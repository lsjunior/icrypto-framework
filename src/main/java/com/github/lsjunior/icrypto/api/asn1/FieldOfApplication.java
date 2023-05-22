package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.DirectoryString;

import com.github.lsjunior.icrypto.ICryptoLog;

public class FieldOfApplication extends ASN1Object {

  private final DirectoryString value;

  public FieldOfApplication(final DirectoryString value) {
    super();
    this.value = value;
  }

  public DirectoryString getValue() {
    return this.value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.value.toASN1Primitive();
  }

  public static FieldOfApplication getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof FieldOfApplication)) {
      return (FieldOfApplication) obj;
    }
    if (obj instanceof ASN1String) {
      return new FieldOfApplication(DirectoryString.getInstance(obj));
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return FieldOfApplication.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
