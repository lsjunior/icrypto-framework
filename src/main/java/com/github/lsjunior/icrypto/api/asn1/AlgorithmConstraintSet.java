package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class AlgorithmConstraintSet extends ASN1Object {

  private AlgorithmConstraints signerAlgorithmConstraints;

  private AlgorithmConstraints eeCertAlgorithmConstraints;

  private AlgorithmConstraints caCertAlgorithmConstraints;

  private AlgorithmConstraints aaCertAlgorithmConstraints;

  private AlgorithmConstraints tsaCertAlgorithmConstraints;

  private AlgorithmConstraintSet(final ASN1Sequence sequence) {
    super();
    for (int i = 0; i < sequence.size(); i++) {
      ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
      int tagNo = taggedObject.getTagNo();
      Object obj = taggedObject.toASN1Primitive();
      switch (tagNo) {
        case 0:
          this.signerAlgorithmConstraints = AlgorithmConstraints.getInstance(obj);
          break;
        case 1:
          this.eeCertAlgorithmConstraints = AlgorithmConstraints.getInstance(obj);
          break;
        case 2:
          this.caCertAlgorithmConstraints = AlgorithmConstraints.getInstance(obj);
          break;
        case 3:
          this.aaCertAlgorithmConstraints = AlgorithmConstraints.getInstance(obj);
          break;
        case 4:
          this.tsaCertAlgorithmConstraints = AlgorithmConstraints.getInstance(obj);
          break;
        default:
          throw new IllegalStateException("Unsupported tagNo " + tagNo);
      }
    }
  }

  public AlgorithmConstraintSet(final AlgorithmConstraints signerAlgorithmConstraints, final AlgorithmConstraints eeCertAlgorithmConstraints,
      final AlgorithmConstraints caCertAlgorithmConstraints, final AlgorithmConstraints aaCertAlgorithmConstraints,
      final AlgorithmConstraints tsaCertAlgorithmConstraints) {
    super();
    this.signerAlgorithmConstraints = signerAlgorithmConstraints;
    this.eeCertAlgorithmConstraints = eeCertAlgorithmConstraints;
    this.caCertAlgorithmConstraints = caCertAlgorithmConstraints;
    this.aaCertAlgorithmConstraints = aaCertAlgorithmConstraints;
    this.tsaCertAlgorithmConstraints = tsaCertAlgorithmConstraints;
  }

  public AlgorithmConstraints getSignerAlgorithmConstraints() {
    return this.signerAlgorithmConstraints;
  }

  public AlgorithmConstraints getEeCertAlgorithmConstraints() {
    return this.eeCertAlgorithmConstraints;
  }

  public AlgorithmConstraints getCaCertAlgorithmConstraints() {
    return this.caCertAlgorithmConstraints;
  }

  public AlgorithmConstraints getAaCertAlgorithmConstraints() {
    return this.aaCertAlgorithmConstraints;
  }

  public AlgorithmConstraints getTsaCertAlgorithmConstraints() {
    return this.tsaCertAlgorithmConstraints;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(Asn1Objects.toAsn1TaggedObject(this.signerAlgorithmConstraints, 0),
        Asn1Objects.toAsn1TaggedObject(this.eeCertAlgorithmConstraints, 1), Asn1Objects.toAsn1TaggedObject(this.caCertAlgorithmConstraints, 2),
        Asn1Objects.toAsn1TaggedObject(this.aaCertAlgorithmConstraints, 3), Asn1Objects.toAsn1TaggedObject(this.tsaCertAlgorithmConstraints, 4));
  }

  public static AlgorithmConstraintSet getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof AlgorithmConstraintSet)) {
      return (AlgorithmConstraintSet) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new AlgorithmConstraintSet((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return AlgorithmConstraintSet.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
