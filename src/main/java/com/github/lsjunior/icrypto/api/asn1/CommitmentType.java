package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x500.DirectoryString;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CommitmentType extends ASN1Object {

  private final ASN1ObjectIdentifier identifier;

  private FieldOfApplication fieldOfApplication;

  private DirectoryString semantics;

  private CommitmentType(final ASN1Sequence sequence) {
    super();
    this.identifier = ASN1ObjectIdentifier.getInstance(Asn1Objects.getObjectAt(sequence, 0));
    if (sequence.size() > 1) {
      for (int i = 1; i < sequence.size(); i++) {
        ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
        int tagNo = taggedObject.getTagNo();
        Object obj = taggedObject.toASN1Primitive();
        switch (tagNo) {
          case 0:
            this.fieldOfApplication = FieldOfApplication.getInstance(obj);
            break;
          case 1:
            this.semantics = DirectoryString.getInstance(obj);
            break;
          default:
            throw new IllegalStateException("Unsupported tagNo " + tagNo);
        }
      }
    }
  }

  public CommitmentType(final ASN1ObjectIdentifier identifier, final FieldOfApplication fieldOfApplication, final DirectoryString semantics) {
    super();
    this.identifier = identifier;
    this.fieldOfApplication = fieldOfApplication;
    this.semantics = semantics;
  }

  public ASN1ObjectIdentifier getIdentifier() {
    return this.identifier;
  }

  public FieldOfApplication getFieldOfApplication() {
    return this.fieldOfApplication;
  }

  public DirectoryString getSemantics() {
    return this.semantics;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.identifier, Asn1Objects.toAsn1TaggedObject(this.fieldOfApplication, 0),
        Asn1Objects.toAsn1TaggedObject(this.semantics, 1));
  }

  public static CommitmentType getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof CommitmentType)) {
      return (CommitmentType) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new CommitmentType((ASN1Sequence) obj);
    }
    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return CommitmentType.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
