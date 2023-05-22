package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CertRevReq extends ASN1Object {

  private final RevReq endCertRevReq;

  private RevReq caCerts;

  private CertRevReq(final ASN1Sequence sequence) {
    super();
    this.endCertRevReq = RevReq.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    if (sequence.size() > 1) {
      ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(1);
      int tagNo = taggedObject.getTagNo();
      Object obj = taggedObject.toASN1Primitive();
      switch (tagNo) {
        case 0:
          this.caCerts = RevReq.getInstance(obj);
          break;
        default:
          throw new IllegalStateException("Unsupported tagNo " + tagNo);
      }
    }
  }

  public CertRevReq(final RevReq endCertRevReq, final RevReq caCerts) {
    super();
    this.endCertRevReq = endCertRevReq;
    this.caCerts = caCerts;
  }

  public RevReq getEndCertRevReq() {
    return this.endCertRevReq;
  }

  public RevReq getCaCerts() {
    return this.caCerts;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.endCertRevReq, this.caCerts);
  }

  public static CertRevReq getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof CertRevReq)) {
      return (CertRevReq) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new CertRevReq((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return CertRevReq.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
