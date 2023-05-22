package com.github.lsjunior.icrypto.api.asn1;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class SignerRules extends ASN1Object {

  private ASN1Boolean externalSignedData;

  private final CmsAttrs mandatedSignedAttr;

  private final CmsAttrs mandatedUnsignedAttr;

  private CertRefReq mandatedCertificateRef;

  private CertInfoReq mandatedCertificateInfo;

  private SignPolExtensions signPolExtensions;

  private SignerRules(final ASN1Sequence sequence) {
    super();
    int index = 0;
    ASN1Encodable obj = sequence.getObjectAt(index);
    if (obj instanceof ASN1Boolean) {
      this.externalSignedData = (ASN1Boolean) obj;
      index++;
    }

    this.mandatedSignedAttr = CmsAttrs.getInstance(Asn1Objects.getObjectAt(sequence, index++));
    this.mandatedUnsignedAttr = CmsAttrs.getInstance(Asn1Objects.getObjectAt(sequence, index++));

    for (int i = index; i < sequence.size(); i++) {
      ASN1TaggedObject taggedObject = (ASN1TaggedObject) sequence.getObjectAt(i);
      int tagNo = taggedObject.getTagNo();
      Object value = taggedObject.toASN1Primitive();
      switch (tagNo) {
        case 0:
          this.mandatedCertificateRef = CertRefReq.getInstance(value);
          break;
        case 1:
          this.mandatedCertificateInfo = CertInfoReq.getInstance(value);
          break;
        case 2:
          this.signPolExtensions = SignPolExtensions.getInstance(value);
          break;
        default:
          throw new IllegalStateException("Unsupported tagNo " + tagNo);
      }
    }
  }

  public SignerRules(final ASN1Boolean externalSignedData, final CmsAttrs mandatedSignedAttr, final CmsAttrs mandatedUnsignedAttr,
      final CertRefReq mandatedCertificateRef, final CertInfoReq mandatedCertificateInfo, final SignPolExtensions signPolExtensions) {
    super();
    this.externalSignedData = externalSignedData;
    this.mandatedSignedAttr = mandatedSignedAttr;
    this.mandatedUnsignedAttr = mandatedUnsignedAttr;
    this.mandatedCertificateRef = mandatedCertificateRef;
    this.mandatedCertificateInfo = mandatedCertificateInfo;
    this.signPolExtensions = signPolExtensions;
  }

  public ASN1Boolean getExternalSignedData() {
    return this.externalSignedData;
  }

  public CmsAttrs getMandatedSignedAttr() {
    return this.mandatedSignedAttr;
  }

  public CmsAttrs getMandatedUnsignedAttr() {
    return this.mandatedUnsignedAttr;
  }

  public CertRefReq getMandatedCertificateRef() {
    return this.mandatedCertificateRef;
  }

  public CertInfoReq getMandatedCertificateInfo() {
    return this.mandatedCertificateInfo;
  }

  public SignPolExtensions getSignPolExtensions() {
    return this.signPolExtensions;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    return Asn1Objects.toAsn1Sequence(this.externalSignedData, this.mandatedSignedAttr, this.mandatedUnsignedAttr,
        Asn1Objects.toAsn1TaggedObject(this.mandatedCertificateRef, 0), Asn1Objects.toAsn1TaggedObject(this.mandatedCertificateInfo, 1),
        Asn1Objects.toAsn1TaggedObject(this.signPolExtensions, 2));
  }

  public static SignerRules getInstance(final Object obj) {
    if ((obj == null) || (obj instanceof SignerRules)) {
      return (SignerRules) obj;
    }
    if (obj instanceof ASN1Sequence) {
      return new SignerRules((ASN1Sequence) obj);
    }

    if (obj instanceof byte[]) {
      try {
        Object tmp = ASN1Primitive.fromByteArray((byte[]) obj);
        return SignerRules.getInstance(tmp);
      } catch (Exception e) {
        ICryptoLog.getLogger().info(e.getMessage(), e);
        throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
      }
    }

    throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
  }

}
