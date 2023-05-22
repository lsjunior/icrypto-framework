package com.github.lsjunior.icrypto.api.asn1;

import java.text.ParseException;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.esf.OtherHashAlgAndValue;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class PolicyInfo extends ASN1Object {

  private SigningPeriod signingPeriod;

  private ASN1GeneralizedTime revocationDate;

  private ASN1ObjectIdentifier policyId;

  private ASN1IA5String policyURI;

  private OtherHashAlgAndValue policyDigest;

  private PolicyInfo(final ASN1Sequence sequence) {
    super();
    int index = 0;

    this.setSigningPeriod(SigningPeriod.getInstance(sequence.getObjectAt(index++)));
    if (sequence.size() == 5) {
      this.setRevocationDate(ASN1GeneralizedTime.getInstance(sequence.getObjectAt(index++)));
    }
    this.setPolicyId(ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(index++)));
    this.setPolicyURI(Asn1Objects.toAsn1Ia5String(sequence.getObjectAt(index++)));
    this.setPolicyDigest(OtherHashAlgAndValue.getInstance(sequence.getObjectAt(index++)));
  }

  public PolicyInfo(final SigningPeriod signingPeriod, final ASN1GeneralizedTime revocationDate, final ASN1ObjectIdentifier policyId, final DERIA5String policyURI, final OtherHashAlgAndValue policyDigest) {
    super();
    this.signingPeriod = signingPeriod;
    this.revocationDate = revocationDate;
    this.policyId = policyId;
    this.policyURI = policyURI;
    this.policyDigest = policyDigest;
  }

  public SigningPeriod getSigningPeriod() {
    return this.signingPeriod;
  }

  protected void setSigningPeriod(final SigningPeriod signingPeriod) {
    this.signingPeriod = signingPeriod;
  }

  public ASN1GeneralizedTime getRevocationDate() {
    return this.revocationDate;
  }

  protected void setRevocationDate(final ASN1GeneralizedTime revocationDate) {
    this.revocationDate = revocationDate;
  }

  public ASN1ObjectIdentifier getPolicyId() {
    return this.policyId;
  }

  protected void setPolicyId(final ASN1ObjectIdentifier policyId) {
    this.policyId = policyId;
  }

  public ASN1IA5String getPolicyURI() {
    return this.policyURI;
  }

  protected void setPolicyURI(final ASN1IA5String policyURI) {
    this.policyURI = policyURI;
  }

  public OtherHashAlgAndValue getPolicyDigest() {
    return this.policyDigest;
  }

  protected void setPolicyDigest(final OtherHashAlgAndValue policyDigest) {
    this.policyDigest = policyDigest;
  }

  public boolean isValid() {
    if (this.getRevocationDate() != null) {
      return false;
    }
    try {
      Date now = new Date();
      Date notBefore = this.getSigningPeriod().getNotBefore().getDate();
      Date notAfter = this.getSigningPeriod().getNotAfter().getDate();
      if ((now.compareTo(notBefore) >= 0) && (now.compareTo(notAfter) <= 0)) {
        return true;
      }
      return false;
    } catch (ParseException e) {
      throw new IllegalStateException(e);
    }
  }

  public ASN1GeneralizedTime getNotBefore() {
    return this.getSigningPeriod().getNotBefore();
  }

  public ASN1GeneralizedTime getNotAfter() {
    return this.getSigningPeriod().getNotAfter();
  }

  @Override
  public String toString() {
    return this.getPolicyId().toString();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(this.getSigningPeriod());
    if (this.getRevocationDate() != null) {
      v.add(this.getRevocationDate());
    }
    v.add(this.getPolicyId());
    v.add(this.getPolicyURI());
    v.add(this.getPolicyDigest());
    return new DERSequence(v);
  }

  public static PolicyInfo getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof PolicyInfo)) {
      return (PolicyInfo) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new PolicyInfo((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return PolicyInfo.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
