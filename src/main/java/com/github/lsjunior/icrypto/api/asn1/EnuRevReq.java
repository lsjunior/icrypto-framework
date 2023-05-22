package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class EnuRevReq extends ASN1Object {

  public static final EnuRevReq CRL_CHECK = new EnuRevReq(new ASN1Enumerated(0));

  public static final EnuRevReq OCSP_CHECK = new EnuRevReq(new ASN1Enumerated(1));

  public static final EnuRevReq BOTH_CHECK = new EnuRevReq(new ASN1Enumerated(2));

  public static final EnuRevReq EITHER_CHECK = new EnuRevReq(new ASN1Enumerated(3));

  public static final EnuRevReq NO_CHECK = new EnuRevReq(new ASN1Enumerated(4));

  public static final EnuRevReq OTHER = new EnuRevReq(new ASN1Enumerated(5));

  private final ASN1Enumerated value;

  private EnuRevReq(final ASN1Sequence sequence) {
    super();
    this.value = ASN1Enumerated.getInstance(Asn1Objects.getObjectAt(sequence, 0));
  }

  public EnuRevReq(final ASN1Enumerated value) {
    super();
    this.value = value;
  }

  public ASN1Enumerated getValue() {
    return this.value;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.value.toASN1Primitive();
  }

  @Override
  public String toString() {
    return this.value.toString();
  }

  public static EnuRevReq getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof EnuRevReq)) {
      return (EnuRevReq) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new EnuRevReq((ASN1Sequence) obj);
    }
    if (obj instanceof ASN1Enumerated) {
      return new EnuRevReq((ASN1Enumerated) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return EnuRevReq.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
