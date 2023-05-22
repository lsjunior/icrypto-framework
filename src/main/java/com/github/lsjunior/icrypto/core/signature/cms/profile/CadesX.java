package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.model.TimeStamp;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.core.certificate.CertPathProvider;
import com.github.lsjunior.icrypto.core.certificate.impl.X509CertificateKeyUsage;
import com.github.lsjunior.icrypto.core.certificate.util.CertPaths;
import com.github.lsjunior.icrypto.core.digest.Digester;
import com.github.lsjunior.icrypto.core.digest.util.Digesters;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;
import com.github.lsjunior.icrypto.core.timestamp.util.TimeStamps;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.ByteStreams;

public class CadesX extends CadesC {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesX() {
    super();
  }

  @SuppressWarnings("unchecked")
  @Override
  protected SignerInformation updateSignerInformation(final CadesSignatureContext context, final CMSSignedData cmsSignedData,
      final SignerInformation currentSignerInformation) throws Exception {
    SignerInformation signerInformation = super.updateSignerInformation(context, cmsSignedData, currentSignerInformation);

    TimeStampProvider ttc = context.getTimeStampClient();

    AttributeTable unsigned = signerInformation.getUnsignedAttributes();
    Hashtable<ASN1ObjectIdentifier, Attribute> hashtable = unsigned.toHashtable();

    // Attributes
    Attribute signatureTimeStampAttribute = hashtable.get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
    Attribute certIdsAttribute = hashtable.get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs);
    Attribute refsAttribute = hashtable.get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs);

    // TimeStamp
    ByteSource signature = ByteSource.wrap(signerInformation.getSignature());
    byte[] toTimeStamp = this.toReferenceTimeStamp(signature, signatureTimeStampAttribute, certIdsAttribute, refsAttribute);

    byte[] timeStamp = ttc.getTimeStamp(Digesters.SHA1.digest(toTimeStamp), DigestType.SHA1);
    ASN1Primitive asn1Primitive = Asn1Objects.toAsn1Primitive(timeStamp);
    DERSet derSet = new DERSet(asn1Primitive);

    Attribute timeStampAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp, derSet);
    hashtable.put(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp, timeStampAttribute);

    AttributeTable newUnsignedAtts = new AttributeTable(hashtable);

    return SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAtts);
  }

  @Override
  public void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    super.doVerify(context, signature);

    // Attributes
    byte[] certificateBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId());
    byte[] revocationBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId());
    byte[] signatureTimeStampBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId());
    byte[] referenceTimeStampBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp.getId());

    if (certificateBytes == null) {
      // context.getErrors().add("Certificate refs attribute not found");
      return;
    }

    if (revocationBytes == null) {
      // context.getErrors().add("Revocation refs attribute not found");
      return;
    }

    if (signatureTimeStampBytes == null) {
      // context.getErrors().add("Signature timestamp attribute not found");
      return;
    }

    if (referenceTimeStampBytes == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.REFERENCE_TIMESTAMP_NOT_FOUND, "References timestamp attribute not found", false));
      return;
    }

    CertPathProvider certPathProvider = context.getCertPathProvider();
    Attribute certIdsAttribute = Attribute.getInstance(certificateBytes);
    Attribute refsAttribute = Attribute.getInstance(revocationBytes);
    Attribute signatureTimeStampAttribute = Attribute.getInstance(signatureTimeStampBytes);
    byte[] toTimeStamp = this.toReferenceTimeStamp(signature.getSignature(), signatureTimeStampAttribute, certIdsAttribute, refsAttribute);

    Attribute referenceTimeStampAttribute = Attribute.getInstance(referenceTimeStampBytes);
    ASN1Set asn1Set = referenceTimeStampAttribute.getAttrValues();
    ASN1Encodable asn1Encodable = asn1Set.getObjectAt(0);
    TimeStamp referenceTimeStamp = TimeStamps.toTimeStamp(asn1Encodable.toASN1Primitive().getEncoded());
    byte[] digest = referenceTimeStamp.getDigest();

    // RockFrameworkLogger.getLogger().info("Calculated reference timestamp: " +
    // Codecs.toHex(Digesters.SHA1.digest(toTimeStamp)));

    DigestType digestType = referenceTimeStamp.getDigestType();
    Digester digester = Digesters.getDigester(digestType);
    byte[] messageDigest = digester.digest(toTimeStamp);

    if (!Arrays.equals(digest, messageDigest)) {
      String digestHex = BaseEncoding.base16().encode(digest);
      String messageDigestHex = BaseEncoding.base16().encode(messageDigest);
      String msg = String.format("Reference timestamp dont match(%s - %s)", digestHex, messageDigestHex);
      signature.getErrors().add(new ErrorMessage(CadesErrors.REFERENCE_TIMESTAMP_INVALID, msg, true));
    }

    List<Certificate> chain = referenceTimeStamp.getChain();
    if ((chain != null) && (!chain.isEmpty())) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.REFERENCE_TIMESTAMP_CERTIFICATE_NOT_FOUND, "Reference timestamp certificate not found", false));
      return;
    }

    Certificate certificate = chain.get(0);
    if (certPathProvider != null) {
      try {
        CertPath certPath = certPathProvider.getCertPath(certificate);
        chain = CertPaths.toCertificate(certPath);
      } catch (CertPathBuilderException e) {
        ICryptoLog.getLogger().debug(e.getMessage(), e);
        signature.getErrors().add(new ErrorMessage(CadesErrors.REFERENCE_TIMESTAMP_CERTIFICATE_INVALID, "Invalid reference timestamp certificate", false));
      }
    }

    X509CertificateKeyUsage certificateKeyUsage = X509CertificateKeyUsage.getInstance(certificate);
    if (!certificateKeyUsage.isExtendedKeyUsageTimestamping()) {
      signature.getErrors()
          .add(new ErrorMessage(CadesErrors.REFERENCE_TIMESTAMP_CERTIFICATE_MISSING_KEY_USAGE, "Missing timestamping key usage in certificate", false));
    }

  }

  private byte[] toReferenceTimeStamp(final ByteSource signature, final Attribute... attributes) throws IOException {
    // RockFrameworkLogger.getLogger().info("Signature: " +
    // Codecs.toHex(Digesters.MD5.digest(signature)));
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    ByteStreams.copy(signature.openStream(), outputStream);
    for (Attribute attribute : attributes) {
      byte[] attrValue = attribute.getAttrValues().getEncoded();
      // RockFrameworkLogger.getLogger().info("Attribute : " + attribute.getAttrType().getId() + " -
      // " +
      // Codecs.toHex(Digesters.MD5.digest(attrValue)));
      outputStream.write(attribute.getAttrType().getEncoded());
      outputStream.write(attrValue);
    }
    return outputStream.toByteArray();
  }

}
