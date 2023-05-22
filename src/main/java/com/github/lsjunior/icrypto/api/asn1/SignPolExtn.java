package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SignPolExtn extends ASN1Object {

  private final ASN1ObjectIdentifier extnID;

  private final ASN1OctetString extnValue;

  private SignPolExtn(final ASN1Sequence sequence) {
    super();
    this.extnID = ASN1ObjectIdentifier.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.extnValue = ASN1OctetString.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public SignPolExtn(final ASN1ObjectIdentifier extnID, final ASN1OctetString extnValue) {
    super();
    this.extnID = extnID;
    this.extnValue = extnValue;
  }

  public ASN1ObjectIdentifier getExtnID() {
    return this.extnID;
  }

  public ASN1OctetString getExtnValue() {
    return this.extnValue;
  }

  @Override
  public String toString() {
    return this.extnID.toString();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.extnID, this.extnValue);
  }

  public static SignPolExtn getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignPolExtn)) {
      return (SignPolExtn) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SignPolExtn((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignPolExtn.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
