package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class RevReq extends ASN1Object {

  private final EnuRevReq enuRevReq;

  private final SignPolExtensions exRevReq;

  private RevReq(final ASN1Sequence sequence) {
    super();
    this.enuRevReq = EnuRevReq.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.exRevReq = SignPolExtensions.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public RevReq(final EnuRevReq enuRevReq, final SignPolExtensions exRevReq) {
    super();
    this.enuRevReq = enuRevReq;
    this.exRevReq = exRevReq;
  }

  public EnuRevReq getEnuRevReq() {
    return this.enuRevReq;
  }

  public SignPolExtensions getExRevReq() {
    return this.exRevReq;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.enuRevReq, this.exRevReq);
  }

  @Override
  public String toString() {
    return this.enuRevReq.toString();
  }

  public static RevReq getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof RevReq)) {
      return (RevReq) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new RevReq((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return RevReq.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
