package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SignaturePolicy extends ASN1Object {

  private final AlgorithmIdentifier signPolicyHashAlg;

  private final SignPolicyInfo signPolicyInfo;

  private final SignPolicyHash signPolicyHash;

  private SignaturePolicy(final ASN1Sequence sequence) {
    super();
    this.signPolicyHashAlg = AlgorithmIdentifier.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.signPolicyInfo = SignPolicyInfo.getInstance(Asn1Objects.getObjectAt(sequence, 1));
    this.signPolicyHash = SignPolicyHash.getInstance(Asn1Objects.getObjectAt(sequence, 2));
  }

  public SignaturePolicy(final AlgorithmIdentifier signPolicyHashAlg, final SignPolicyInfo signPolicyInfo, final SignPolicyHash signPolicyHash) {
    super();
    this.signPolicyHashAlg = signPolicyHashAlg;
    this.signPolicyInfo = signPolicyInfo;
    this.signPolicyHash = signPolicyHash;
  }

  public AlgorithmIdentifier getSignPolicyHashAlg() {
    return this.signPolicyHashAlg;
  }

  public SignPolicyInfo getSignPolicyInfo() {
    return this.signPolicyInfo;
  }

  public SignPolicyHash getSignPolicyHash() {
    return this.signPolicyHash;
  }

  @Override
  public String toString() {
    return this.signPolicyInfo.toString();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.signPolicyHashAlg, this.signPolicyInfo, this.signPolicyHash);
  }

  public static SignaturePolicy getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignaturePolicy)) {
      return (SignaturePolicy) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SignaturePolicy((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignaturePolicy.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
