package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CommonRules extends ASN1Object {

  private SignerAndVerifierRules signerAndVerifierRules;

  private SigningCertTrustCondition signingCertTrustCondition;

  private TimestampTrustCondition timeStampTrustCondition;

  private AttributeTrustCondition attributeTrustCondition;

  private AlgorithmConstraintSet algorithmConstraintSet;

  private SignPolExtensions signPolExtensions;

  private CommonRules(final ASN1Sequence sequence) {
    super();
    for (int i = 0; i < sequence.size(); i++) {
      ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
      int tagNo = taggedObject.getTagNo();
      Object obj = taggedObject.toASN1Primitive();
      switch (tagNo) {
        case 0:
          this.signerAndVerifierRules = SignerAndVerifierRules.getInstance(obj);
          break;
        case 1:
          this.signingCertTrustCondition = SigningCertTrustCondition.getInstance(obj);
          break;
        case 2:
          this.timeStampTrustCondition = TimestampTrustCondition.getInstance(obj);
          break;
        case 3:
          this.attributeTrustCondition = AttributeTrustCondition.getInstance(obj);
          break;
        case 4:
          this.algorithmConstraintSet = AlgorithmConstraintSet.getInstance(obj);
          break;
        case 5:
          this.signPolExtensions = SignPolExtensions.getInstance(obj);
          break;
        default:
          throw new IllegalStateException("Unsupported tagNo " + tagNo);
      }
    }
  }

  public CommonRules(final SignerAndVerifierRules signerAndVeriferRules, final SigningCertTrustCondition signingCertTrustCondition,
      final TimestampTrustCondition timeStampTrustCondition, final AttributeTrustCondition attributeTrustCondition,
      final AlgorithmConstraintSet algorithmConstraintSet, final SignPolExtensions signPolExtensions) {
    super();
    this.signerAndVerifierRules = signerAndVeriferRules;
    this.signingCertTrustCondition = signingCertTrustCondition;
    this.timeStampTrustCondition = timeStampTrustCondition;
    this.attributeTrustCondition = attributeTrustCondition;
    this.algorithmConstraintSet = algorithmConstraintSet;
    this.signPolExtensions = signPolExtensions;
  }

  public SignerAndVerifierRules getSignerAndVerifierRules() {
    return this.signerAndVerifierRules;
  }

  public SigningCertTrustCondition getSigningCertTrustCondition() {
    return this.signingCertTrustCondition;
  }

  public TimestampTrustCondition getTimeStampTrustCondition() {
    return this.timeStampTrustCondition;
  }

  public AttributeTrustCondition getAttributeTrustCondition() {
    return this.attributeTrustCondition;
  }

  public AlgorithmConstraintSet getAlgorithmConstraintSet() {
    return this.algorithmConstraintSet;
  }

  public SignPolExtensions getSignPolExtensions() {
    return this.signPolExtensions;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(Asn1Objects.toAsn1TaggedObject(this.signerAndVerifierRules, 0),
        Asn1Objects.toAsn1TaggedObject(this.signingCertTrustCondition, 1), Asn1Objects.toAsn1TaggedObject(this.timeStampTrustCondition, 2),
        Asn1Objects.toAsn1TaggedObject(this.attributeTrustCondition, 3), Asn1Objects.toAsn1TaggedObject(this.algorithmConstraintSet, 4),
        Asn1Objects.toAsn1TaggedObject(this.signPolExtensions, 5));
  }

  public static CommonRules getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof CommonRules)) {
      return (CommonRules) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new CommonRules((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return CommonRules.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
