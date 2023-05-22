package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class MandatedUnsignedAttr extends CmsAttrs {

  public MandatedUnsignedAttr() {
    super();
  }

  private MandatedUnsignedAttr(final ASN1Sequence sequence) {
    super(sequence);
  }

  public static MandatedUnsignedAttr getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof MandatedUnsignedAttr)) {
      return (MandatedUnsignedAttr) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new MandatedUnsignedAttr((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return MandatedUnsignedAttr.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
