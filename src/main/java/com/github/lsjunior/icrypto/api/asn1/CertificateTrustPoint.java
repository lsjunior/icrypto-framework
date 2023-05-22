package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.NameConstraints;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CertificateTrustPoint extends ASN1Object {

  private final Certificate trustpoint;

  private PathLenConstraint pathLenConstraint;

  private AcceptablePolicySet acceptablePolicySet;

  private NameConstraints nameConstraints;

  private PolicyConstraints policyConstraints;

  private CertificateTrustPoint(final ASN1Sequence sequence) {
    super();
    this.trustpoint = Certificate.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    if (sequence.size() > 1) {
      for (int i = 1; i < sequence.size(); i++) {
        ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
        int tagNo = taggedObject.getTagNo();
        Object obj = taggedObject.toASN1Primitive();
        switch (tagNo) {
          case 0:
            this.pathLenConstraint = PathLenConstraint.getInstance(obj);
            break;
          case 1:
            this.acceptablePolicySet = AcceptablePolicySet.getInstance(obj);
            break;
          case 2:
            this.nameConstraints = NameConstraints.getInstance(obj);
            break;
          case 3:
            this.policyConstraints = PolicyConstraints.getInstance(obj);
            break;
          default:
            throw new IllegalStateException("Unsupported tagNo " + tagNo);
        }
      }
    }
  }

  public CertificateTrustPoint(final Certificate trustpoint, final PathLenConstraint pathLenConstraint, final AcceptablePolicySet acceptablePolicySet,
      final NameConstraints nameConstraints, final PolicyConstraints policyConstraints) {
    super();
    this.trustpoint = trustpoint;
    this.pathLenConstraint = pathLenConstraint;
    this.acceptablePolicySet = acceptablePolicySet;
    this.nameConstraints = nameConstraints;
    this.policyConstraints = policyConstraints;
  }

  public Certificate getTrustpoint() {
    return this.trustpoint;
  }

  public PathLenConstraint getPathLenConstraint() {
    return this.pathLenConstraint;
  }

  public AcceptablePolicySet getAcceptablePolicySet() {
    return this.acceptablePolicySet;
  }

  public NameConstraints getNameConstraints() {
    return this.nameConstraints;
  }

  public PolicyConstraints getPolicyConstraints() {
    return this.policyConstraints;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.trustpoint, Asn1Objects.toAsn1TaggedObject(this.pathLenConstraint, 0),
        Asn1Objects.toAsn1TaggedObject(this.acceptablePolicySet, 1), Asn1Objects.toAsn1TaggedObject(this.nameConstraints, 2),
        Asn1Objects.toAsn1TaggedObject(this.policyConstraints, 3));
  }

  @Override
  public String toString() {
    return this.trustpoint.toString();
  }

  public static CertificateTrustPoint getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof CertificateTrustPoint)) {
      return (CertificateTrustPoint) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new CertificateTrustPoint((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return CertificateTrustPoint.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
