package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.NameConstraints;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class TimestampTrustCondition extends ASN1Object {

  private CertificateTrustTrees ttsCertificateTrustTrees;

  private CertRevReq ttsRevReq;

  private NameConstraints ttsNameConstraints;

  private DeltaTime cautionPeriod;

  private DeltaTime signatureTimestampDelay;

  private TimestampTrustCondition(final ASN1Sequence sequence) {
    super();
    for (int i = 0; i < sequence.size(); i++) {
      ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
      int tagNo = taggedObject.getTagNo();
      Object obj = taggedObject.toASN1Primitive();
      switch (tagNo) {
        case 0:
          this.ttsCertificateTrustTrees = CertificateTrustTrees.getInstance(obj);
          break;
        case 1:
          this.ttsRevReq = CertRevReq.getInstance(obj);
          break;
        case 2:
          this.ttsNameConstraints = NameConstraints.getInstance(obj);
          break;
        case 3:
          this.cautionPeriod = DeltaTime.getInstance(obj);
          break;
        case 4:
          this.signatureTimestampDelay = DeltaTime.getInstance(obj);
          break;
        default:
          throw new IllegalStateException("Unsupported tagNo " + tagNo);
      }
    }
  }

  public TimestampTrustCondition(final CertificateTrustTrees ttsCertificateTrustTrees, final CertRevReq ttsRevReq, final NameConstraints ttsNameConstraints,
      final DeltaTime cautionPeriod, final DeltaTime signatureTimestampDelay) {
    super();
    this.ttsCertificateTrustTrees = ttsCertificateTrustTrees;
    this.ttsRevReq = ttsRevReq;
    this.ttsNameConstraints = ttsNameConstraints;
    this.cautionPeriod = cautionPeriod;
    this.signatureTimestampDelay = signatureTimestampDelay;
  }

  public CertificateTrustTrees getTtsCertificateTrustTrees() {
    return this.ttsCertificateTrustTrees;
  }

  public CertRevReq getTtsRevReq() {
    return this.ttsRevReq;
  }

  public NameConstraints getTtsNameConstraints() {
    return this.ttsNameConstraints;
  }

  public DeltaTime getCautionPeriod() {
    return this.cautionPeriod;
  }

  public DeltaTime getSignatureTimestampDelay() {
    return this.signatureTimestampDelay;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(Asn1Objects.toAsn1TaggedObject(this.ttsCertificateTrustTrees, 0), Asn1Objects.toAsn1TaggedObject(this.ttsRevReq, 1),
        Asn1Objects.toAsn1TaggedObject(this.ttsNameConstraints, 2), Asn1Objects.toAsn1TaggedObject(this.cautionPeriod, 3),
        Asn1Objects.toAsn1TaggedObject(this.signatureTimestampDelay, 4));
  }

  public static TimestampTrustCondition getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof TimestampTrustCondition)) {
      return (TimestampTrustCondition) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new TimestampTrustCondition((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return TimestampTrustCondition.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
