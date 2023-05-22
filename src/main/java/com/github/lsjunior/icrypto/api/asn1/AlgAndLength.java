package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class AlgAndLength extends ASN1Object {

  private final ASN1ObjectIdentifier algID;

  private final ASN1Integer minKeyLength;

  private final SignPolExtensions other;

  private AlgAndLength(final ASN1Sequence sequence) {
    super();
    this.algID = ASN1ObjectIdentifier.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.minKeyLength = ASN1Integer.getInstance(Asn1Objects.getObjectAt(sequence, 1));
    this.other = SignPolExtensions.getInstance(Asn1Objects.getObjectAt(sequence, 2));
  }

  public AlgAndLength(final ASN1ObjectIdentifier algID, final ASN1Integer minKeyLength, final SignPolExtensions other) {
    super();
    this.algID = algID;
    this.minKeyLength = minKeyLength;
    this.other = other;
  }

  public ASN1ObjectIdentifier getAlgID() {
    return this.algID;
  }

  public ASN1Integer getMinKeyLength() {
    return this.minKeyLength;
  }

  public SignPolExtensions getOther() {
    return this.other;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.algID, this.minKeyLength, this.other);
  }

  @Override
  public String toString() {
    return this.algID.toString();
  }

  public static AlgAndLength getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AlgAndLength)) {
      return (AlgAndLength) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new AlgAndLength((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AlgAndLength.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
