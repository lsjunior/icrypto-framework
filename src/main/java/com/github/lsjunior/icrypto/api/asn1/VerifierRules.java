package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class VerifierRules extends ASN1Object {

  private final MandatedUnsignedAttr mandatedUnsignedAttr;

  private final SignPolExtensions signPolExtensions;

  private VerifierRules(final ASN1Sequence sequence) {
    super();
    this.mandatedUnsignedAttr = MandatedUnsignedAttr.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.signPolExtensions = SignPolExtensions.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public VerifierRules(final MandatedUnsignedAttr mandatedUnsignedAttr, final SignPolExtensions signPolExtensions) {
    super();
    this.mandatedUnsignedAttr = mandatedUnsignedAttr;
    this.signPolExtensions = signPolExtensions;
  }

  public MandatedUnsignedAttr getMandatedUnsignedAttr() {
    return this.mandatedUnsignedAttr;
  }

  public SignPolExtensions getSignPolExtensions() {
    return this.signPolExtensions;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.mandatedUnsignedAttr, this.signPolExtensions);
  }

  public static VerifierRules getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof VerifierRules)) {
      return (VerifierRules) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new VerifierRules((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return VerifierRules.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
