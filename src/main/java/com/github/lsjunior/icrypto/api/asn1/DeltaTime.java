package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class DeltaTime extends ASN1Object {

  private final ASN1Integer deltaSeconds;

  private final ASN1Integer deltaMinutes;

  private final ASN1Integer deltaHours;

  private final ASN1Integer deltaDays;

  private DeltaTime(final ASN1Sequence sequence) {
    super();
    this.deltaSeconds = ASN1Integer.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.deltaMinutes = ASN1Integer.getInstance(Asn1Objects.getObjectAt(sequence, 1));
    this.deltaHours = ASN1Integer.getInstance(Asn1Objects.getObjectAt(sequence, 2));
    this.deltaDays = ASN1Integer.getInstance(Asn1Objects.getObjectAt(sequence, 3));
  }

  public DeltaTime(final ASN1Integer deltaSeconds, final ASN1Integer deltaMinutes, final ASN1Integer deltaHours, final ASN1Integer deltaDays) {
    super();
    this.deltaSeconds = deltaSeconds;
    this.deltaMinutes = deltaMinutes;
    this.deltaHours = deltaHours;
    this.deltaDays = deltaDays;
  }

  public ASN1Integer getDeltaSeconds() {
    return this.deltaSeconds;
  }

  public ASN1Integer getDeltaMinutes() {
    return this.deltaMinutes;
  }

  public ASN1Integer getDeltaHours() {
    return this.deltaHours;
  }

  public ASN1Integer getDeltaDays() {
    return this.deltaDays;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.deltaSeconds, this.deltaMinutes, this.deltaHours, this.deltaDays);
  }

  public static DeltaTime getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof DeltaTime)) {
      return (DeltaTime) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new DeltaTime((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return DeltaTime.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
