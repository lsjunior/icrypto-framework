package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class PdfEntry extends ASN1Object {

  private final ASN1UTF8String id;

  private final ASN1UTF8String value;

  private PdfEntry(final ASN1Sequence sequence) {
    super();
    this.id = ASN1UTF8String.getInstance(sequence.getObjectAt(0));
    if (sequence.size() == 2) {
      this.value = ASN1UTF8String.getInstance(sequence.getObjectAt(1));
    } else {
      this.value = null;
    }
  }

  public PdfEntry(final ASN1UTF8String id, final ASN1UTF8String value) {
    super();
    this.id = id;
    this.value = value;
  }

  public ASN1UTF8String getId() {
    return this.id;
  }

  public ASN1UTF8String getValue() {
    return this.value;
  }

  @Override
  public String toString() {
    return this.getId().toString();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(this.getId());
    if (this.getValue() != null) {
      v.add(this.getValue());
    }
    return new DERSequence(v);
  }

  public static PdfEntry getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof PdfEntry)) {
      return (PdfEntry) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new PdfEntry((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return PdfEntry.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
