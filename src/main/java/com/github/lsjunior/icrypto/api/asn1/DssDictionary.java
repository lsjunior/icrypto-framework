package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class DssDictionary extends ASN1Object {

  private final ASN1Sequence mandatedEntries;

  private final ASN1Sequence vriMandatedEntries;

  public DssDictionary(final ASN1Sequence sequence) {
    super();
    this.mandatedEntries = ASN1Sequence.getInstance(sequence.getObjectAt(0));
    if (sequence.size() == 2) {
      this.vriMandatedEntries = ASN1Sequence.getInstance(sequence.getObjectAt(1));
    } else {
      this.vriMandatedEntries = null;
    }
  }

  public ASN1Sequence getMandatedEntries() {
    return this.mandatedEntries;
  }

  public ASN1Sequence getVriMandatedEntries() {
    return this.vriMandatedEntries;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(this.getMandatedEntries());
    if (this.getVriMandatedEntries() != null) {
      v.add(this.getVriMandatedEntries());
    }
    return new DERSequence(v);
  }

  public static DssDictionary getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof DssDictionary)) {
      return (DssDictionary) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new DssDictionary((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return DssDictionary.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
