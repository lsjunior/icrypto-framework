package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class Lpa extends ASN1Object {

  private Version version;

  private final PolicyInfos policyInfos;

  private final ASN1GeneralizedTime nextUpdate;

  private Lpa(final ASN1Sequence sequence) {
    super();
    int index = 0;
    if (sequence.size() == 3) {
      this.version = Version.getInstance(sequence.getObjectAt(index++));
    } else {
      this.version = new Version(new ASN1Integer(2));
    }
    this.policyInfos = PolicyInfos.getInstance(sequence.getObjectAt(index++));
    this.nextUpdate = ASN1GeneralizedTime.getInstance(sequence.getObjectAt(index++));
  }

  public Lpa(final Version version, final PolicyInfos policyInfos, final ASN1GeneralizedTime nextUpdate) {
    super();
    this.version = version;
    this.policyInfos = policyInfos;
    this.nextUpdate = nextUpdate;
  }

  public Version getVersion() {
    return this.version;
  }

  public PolicyInfos getPolicyInfos() {
    return this.policyInfos;
  }

  public ASN1GeneralizedTime getNextUpdate() {
    return this.nextUpdate;
  }

  // Helper
  public PolicyInfo getPolicyById(final String id) {
    return this.policyInfos.getPolicyById(id);
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    if (this.version != null) {
      v.add(this.version);
    }
    v.add(this.policyInfos);
    v.add(this.nextUpdate);
    return new DERSequence(v);
  }

  public static Lpa getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof Lpa)) {
      return (Lpa) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new Lpa((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return Lpa.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
