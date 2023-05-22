package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class PolicyConstraints extends ASN1Object {

  private final SkipCerts requireExplicitPolicy;

  private final SkipCerts inhibitPolicyMapping;

  private PolicyConstraints(final ASN1Sequence sequence) {
    super();
    this.requireExplicitPolicy = SkipCerts.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    this.inhibitPolicyMapping = SkipCerts.getInstance(Asn1Objects.getObjectAt(sequence, 1));
  }

  public PolicyConstraints(final SkipCerts requireExplicitPolicy, final SkipCerts inhibitPolicyMapping) {
    super();
    this.requireExplicitPolicy = requireExplicitPolicy;
    this.inhibitPolicyMapping = inhibitPolicyMapping;
  }

  public SkipCerts getRequireExplicitPolicy() {
    return this.requireExplicitPolicy;
  }

  public SkipCerts getInhibitPolicyMapping() {
    return this.inhibitPolicyMapping;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.requireExplicitPolicy, this.inhibitPolicyMapping);
  }

  public static PolicyConstraints getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof PolicyConstraints)) {
      return (PolicyConstraints) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new PolicyConstraints((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return PolicyConstraints.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
