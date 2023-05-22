package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SignPolicyInfo extends ASN1Object {

  private final SignPolicyId signPolicyIdentifier;

  private final ASN1GeneralizedTime dateOfIssue;

  private final PolicyIssuerName policyIssueName;

  private final FieldOfApplication fieldOfApplication;

  private final SignatureValidationPolicy signatureValidationPolicy;

  private final SignPolExtensions signPolExtensions;

  private SignPolicyInfo(final ASN1Sequence sequence) {
    super();
    this.signPolicyIdentifier = SignPolicyId.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.dateOfIssue = ASN1GeneralizedTime.getInstance(Asn1Objects.getObjectAt(sequence, 1));
    this.policyIssueName = PolicyIssuerName.getInstance(Asn1Objects.getObjectAt(sequence, 2));
    this.fieldOfApplication = FieldOfApplication.getInstance(Asn1Objects.getObjectAt(sequence, 3));
    this.signatureValidationPolicy = SignatureValidationPolicy.getInstance(Asn1Objects.getObjectAt(sequence, 4));
    this.signPolExtensions = SignPolExtensions.getInstance(Asn1Objects.getObjectAt(sequence, 5));
  }

  public SignPolicyInfo(final SignPolicyId signPolicyIdentifier, final ASN1GeneralizedTime dateOfIssue, final PolicyIssuerName policyIssueName,
      final FieldOfApplication fieldOfApplication, final SignatureValidationPolicy signatureValidationPolicy, final SignPolExtensions signPolExtensions) {
    super();
    this.signPolicyIdentifier = signPolicyIdentifier;
    this.dateOfIssue = dateOfIssue;
    this.policyIssueName = policyIssueName;
    this.fieldOfApplication = fieldOfApplication;
    this.signatureValidationPolicy = signatureValidationPolicy;
    this.signPolExtensions = signPolExtensions;
  }

  public SignPolicyId getSignPolicyIdentifier() {
    return this.signPolicyIdentifier;
  }

  public ASN1GeneralizedTime getDateOfIssue() {
    return this.dateOfIssue;
  }

  public PolicyIssuerName getPolicyIssueName() {
    return this.policyIssueName;
  }

  public FieldOfApplication getFieldOfApplication() {
    return this.fieldOfApplication;
  }

  public SignatureValidationPolicy getSignatureValidationPolicy() {
    return this.signatureValidationPolicy;
  }

  public SignPolExtensions getSignPolExtensions() {
    return this.signPolExtensions;
  }

  @Override
  public String toString() {
    return this.signPolicyIdentifier.toString();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.signPolicyIdentifier, this.dateOfIssue, this.policyIssueName, this.fieldOfApplication,
        this.signatureValidationPolicy, this.signPolExtensions);
  }

  public static SignPolicyInfo getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignPolicyInfo)) {
      return (SignPolicyInfo) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SignPolicyInfo((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignPolicyInfo.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
