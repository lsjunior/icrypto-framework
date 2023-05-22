package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.IOException;
import java.io.InputStream;
import java.security.Provider;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.digest.util.Digesters;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;
import com.google.common.base.Strings;
import com.google.common.io.ByteStreams;

public class LocalSignatureInterface implements SignatureInterface {

  private final Identity identity;

  private final String algorithm;

  private Provider provider;

  private String providerName;

  private TimeStampProvider timeStampProvider;

  public LocalSignatureInterface(final Identity identity, final String algorithm) {
    super();
    this.identity = identity;
    this.algorithm = algorithm;
  }

  public LocalSignatureInterface(final Identity identity, final String algorithm, final String providerName, final TimeStampProvider timeStampProvider) {
    super();
    this.identity = identity;
    this.algorithm = algorithm;
    this.providerName = providerName;
    this.timeStampProvider = timeStampProvider;
  }

  public LocalSignatureInterface(final Identity identity, final String algorithm, final Provider provider, final TimeStampProvider timeStampProvider) {
    super();
    this.identity = identity;
    this.algorithm = algorithm;
    this.provider = provider;
    this.timeStampProvider = timeStampProvider;
  }

  @Override
  public byte[] sign(final InputStream content) throws IOException {
    try {
      List<Certificate> chain = this.identity.getChain();
      X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(chain.get(0).getEncoded());
      DigestCalculatorProvider digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().build();
      JcaCertStore jcaCertStore = new JcaCertStore(chain);
      CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(this.algorithm);
      if (this.provider != null) {
        contentSignerBuilder.setProvider(this.provider);
      }
      if (!Strings.isNullOrEmpty(this.providerName)) {
        contentSignerBuilder.setProvider(this.providerName);
      }
      ContentSigner contentSigner = contentSignerBuilder.build(this.identity.getPrivateKey());
      SignerInfoGenerator signerInfoGenerator = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider).build(contentSigner, x509CertificateHolder);
      cmsSignedDataGenerator.addSignerInfoGenerator(signerInfoGenerator);
      cmsSignedDataGenerator.addCertificates(jcaCertStore);
      CMSProcessableByteArray msg = new CMSProcessableByteArray(ByteStreams.toByteArray(content));
      CMSSignedData signedData = cmsSignedDataGenerator.generate(msg, false);
      if (this.timeStampProvider != null) {
        signedData = this.signTimeStamps(signedData);
      }
      return signedData.getEncoded();
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  protected CMSSignedData signTimeStamps(final CMSSignedData signedData) throws IOException {
    SignerInformationStore signerStore = signedData.getSignerInfos();
    List<SignerInformation> newSigners = new ArrayList<>();

    for (SignerInformation signer : signerStore.getSigners()) {
      newSigners.add(this.signTimeStamp(signer));
    }

    return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
  }

  protected SignerInformation signTimeStamp(final SignerInformation signer) throws IOException {
    AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

    ASN1EncodableVector vector = new ASN1EncodableVector();
    if (unsignedAttributes != null) {
      vector = unsignedAttributes.toASN1EncodableVector();
    }

    byte[] token = this.timeStampProvider.getTimeStamp(Digesters.SHA1.digest(signer.getSignature()), DigestType.SHA1);
    ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
    ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

    vector.add(signatureTimeStamp);
    Attributes signedAttributes = new Attributes(vector);

    SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(signedAttributes));
    return newSigner;
  }

}
