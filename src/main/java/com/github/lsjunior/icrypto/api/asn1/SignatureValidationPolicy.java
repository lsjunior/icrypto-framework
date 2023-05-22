package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SignatureValidationPolicy extends ASN1Object {

  private final SigningPeriod signingPeriod;

  private final CommonRules commonRules;

  private final CommitmentRules commitmentRules;

  private final SignPolExtensions signPolExtensions;

  private SignatureValidationPolicy(final ASN1Sequence sequence) {
    super();
    this.signingPeriod = SigningPeriod.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.commonRules = CommonRules.getInstance(Asn1Objects.getObjectAt(sequence, 1));
    this.commitmentRules = CommitmentRules.getInstance(Asn1Objects.getObjectAt(sequence, 2));
    this.signPolExtensions = SignPolExtensions.getInstance(Asn1Objects.getObjectAt(sequence, 3));
  }

  public SignatureValidationPolicy(final SigningPeriod signingPeriod, final CommonRules commonRules, final CommitmentRules commitmentRules,
      final SignPolExtensions signPolExtensions) {
    super();
    this.signingPeriod = signingPeriod;
    this.commonRules = commonRules;
    this.commitmentRules = commitmentRules;
    this.signPolExtensions = signPolExtensions;
  }

  public SigningPeriod getSigningPeriod() {
    return this.signingPeriod;
  }

  public CommonRules getCommonRules() {
    return this.commonRules;
  }

  public CommitmentRules getCommitmentRules() {
    return this.commitmentRules;
  }

  public SignPolExtensions getSignPolExtensions() {
    return this.signPolExtensions;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.signingPeriod, this.commonRules, this.commitmentRules, this.signPolExtensions);
  }

  public static SignatureValidationPolicy getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignatureValidationPolicy)) {
      return (SignatureValidationPolicy) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SignatureValidationPolicy((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignatureValidationPolicy.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
