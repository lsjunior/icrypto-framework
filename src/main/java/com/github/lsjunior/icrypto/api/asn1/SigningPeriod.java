package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SigningPeriod extends ASN1Object {

  private final ASN1GeneralizedTime notBefore;

  private final ASN1GeneralizedTime notAfter;

  private SigningPeriod(final ASN1Sequence sequence) {
    super();
    this.notBefore = ASN1GeneralizedTime.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.notAfter = ASN1GeneralizedTime.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public SigningPeriod(final ASN1GeneralizedTime notBefore, final ASN1GeneralizedTime notAfter) {
    super();
    this.notBefore = notBefore;
    this.notAfter = notAfter;

  }

  public ASN1GeneralizedTime getNotBefore() {
    return this.notBefore;
  }

  public ASN1GeneralizedTime getNotAfter() {
    return this.notAfter;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.notAfter, this.notBefore);
  }

  public static SigningPeriod getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SigningPeriod)) {
      return (SigningPeriod) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SigningPeriod((ASN1Sequence) obj);
    }
    if (obj instanceof ASN1GeneralizedTime) {
      return new SigningPeriod((ASN1GeneralizedTime) obj, null);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SigningPeriod.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
