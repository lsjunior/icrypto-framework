package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SignerAndVerifierRules extends ASN1Object {

  private final SignerRules signerRules;

  private final VerifierRules verifierRules;

  private SignerAndVerifierRules(final ASN1Sequence sequence) {
    super();
    this.signerRules = SignerRules.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.verifierRules = VerifierRules.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public SignerAndVerifierRules(final SignerRules signerRules, final VerifierRules verifierRules) {
    super();
    this.signerRules = signerRules;
    this.verifierRules = verifierRules;
  }

  public SignerRules getSignerRules() {
    return this.signerRules;
  }

  public VerifierRules getVerifierRules() {
    return this.verifierRules;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.signerRules, this.verifierRules);
  }

  public static SignerAndVerifierRules getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignerAndVerifierRules)) {
      return (SignerAndVerifierRules) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SignerAndVerifierRules((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignerAndVerifierRules.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
