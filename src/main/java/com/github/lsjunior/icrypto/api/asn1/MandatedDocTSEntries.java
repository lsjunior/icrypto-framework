package com.github.lsjunior.icrypto.api.asn1;

import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import com.github.lsjunior.icrypto.ICryptoLog;

public class MandatedDocTSEntries extends ASN1Object {

  private final ASN1Sequence sequence;

  public MandatedDocTSEntries(final ASN1Sequence sequence) {
    super();
    this.sequence = sequence;
  }

  public int size() {
    return this.sequence.size();
  }

  public PdfEntry getEntryAt(final int index) {
    PdfEntry entry = (PdfEntry) this.sequence.getObjectAt(index);
    return entry;
  }

  public PdfEntry getEntryById(final String id) {
    for (int i = 0; i < this.sequence.size(); i++) {
      PdfEntry entry = this.getEntryAt(i);
      String entryId = entry.getId().getString();
      if (id.equals(entryId)) {
        return entry;
      }
    }
    return null;
  }

  @SuppressWarnings("rawtypes")
  public Enumeration getObjects() {
    return this.sequence.getObjects();
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return this.sequence;
  }

  public static MandatedDocTSEntries getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof MandatedDocTSEntries)) {
      return (MandatedDocTSEntries) obj;
    }
    if (obj instanceof ASN1Sequence) {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      ASN1Sequence as = (ASN1Sequence) obj;
      for (int i = 0; i < as.size(); i++) {
        vector.add(PdfEntry.getInstance(as.getObjectAt(i)));
      }
      DERSequence sequence = new DERSequence(vector);
      return new MandatedDocTSEntries(sequence);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return MandatedDocTSEntries.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
