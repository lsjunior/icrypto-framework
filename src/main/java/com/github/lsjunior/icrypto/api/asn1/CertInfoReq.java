package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CertInfoReq extends ASN1Object {

  public static final CertInfoReq NONE = new CertInfoReq(new ASN1Enumerated(0));

  public static final CertInfoReq SIGNER_ONLY = new CertInfoReq(new ASN1Enumerated(1));

  public static final CertInfoReq FULL_PATH = new CertInfoReq(new ASN1Enumerated(2));

  private final ASN1Enumerated value;

  private CertInfoReq(final ASN1Sequence sequence) {
    super();
    this.value = ASN1Enumerated.getInstance(Asn1Objects.getObjectAt(sequence, 0));
  }

  public CertInfoReq(final ASN1Enumerated value) {
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

  public static CertInfoReq getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof CertInfoReq)) {
      return (CertInfoReq) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new CertInfoReq((ASN1Sequence) obj);
    }
    if (obj instanceof ASN1Enumerated) {
      return new CertInfoReq((ASN1Enumerated) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return CertInfoReq.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
