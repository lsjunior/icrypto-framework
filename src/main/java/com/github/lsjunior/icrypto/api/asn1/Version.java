package com.github.lsjunior.icrypto.api.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;

import com.github.lsjunior.icrypto.ICryptoLog;

public class Version extends ASN1Object {

  private final ASN1Integer version;

  public Version(final ASN1Integer version) {
    super();
    this.version = version;
  }

  public BigInteger getValue() {
    return this.version.getValue();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.version.toASN1Primitive();
  }

  public static Version getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof Version)) {
      return (Version) obj;
    }
    if (obj instanceof ASN1Integer) {
      return new Version((ASN1Integer) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return Version.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
