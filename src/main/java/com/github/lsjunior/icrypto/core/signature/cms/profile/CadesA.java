package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.ESFAttributes;
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
import com.github.lsjunior.icrypto.core.digest.util.Digesters;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesServiceHelper;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CadesA extends CadesXl {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesA() {
    super();
  }

  @SuppressWarnings("unchecked")
  @Override
  protected SignerInformation updateSignerInformation(final CadesSignatureContext context, final CMSSignedData cmsSignedData,
      final SignerInformation currentSignerInformation) throws Exception {
    SignerInformation signerInformation = super.updateSignerInformation(context, cmsSignedData, currentSignerInformation);

    byte[] timeStampData = CadesServiceHelper.getArchiveTimeStampData(cmsSignedData, signerInformation);

    if (timeStampData != null) {
      TimeStampProvider ttc = context.getTimeStampClient();
      byte[] timeStamp = ttc.getTimeStamp(Digesters.SHA1.digest(timeStampData), DigestType.SHA1);
      ASN1Primitive asn1Primitive = Asn1Objects.toAsn1Primitive(timeStamp);
      DERSet derSet = new DERSet(asn1Primitive);

      AttributeTable unsigned = signerInformation.getUnsignedAttributes();
      Hashtable<ASN1ObjectIdentifier, Attribute> hashtable = unsigned.toHashtable();

      Attribute timeStampAttribute = new Attribute(ESFAttributes.archiveTimestampV2, derSet);
      hashtable.put(ESFAttributes.archiveTimestampV2, timeStampAttribute);

      if (hashtable.contains(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken)) {
        hashtable.remove(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken);
      }

      if (hashtable.contains(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp)) {
        hashtable.remove(PKCSObjectIdentifiers.id_aa_ets_escTimeStamp);
      }

      AttributeTable newUnsignedAtts = new AttributeTable(hashtable);

      return SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAtts);
    }

    return signerInformation;
  }

  @Override
  public void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    super.doVerify(context, signature);
    TimeStamp timeStamp = signature.getArchiveTimeStamp();
    CertPathProvider certPathProvider = context.getCertPathProvider();

    if (timeStamp == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.ARCHIVE_TIMESTAMP_NOT_FOUND, "Archive timestamp attribute not found", false));
      return;
    }

    List<Certificate> chain = timeStamp.getChain();
    if ((chain != null) && (!chain.isEmpty())) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.ARCHIVE_TIMESTAMP_CERTIFICATE_NOT_FOUND, "Archive timestamp certificate not found", false));
      return;
    }

    Certificate certificate = chain.get(0);
    if (certPathProvider != null) {
      try {
        CertPath certPath = certPathProvider.getCertPath(certificate);
        chain = CertPaths.toCertificate(certPath);
      } catch (CertPathBuilderException e) {
        ICryptoLog.getLogger().debug(e.getMessage(), e);
        signature.getErrors().add(new ErrorMessage(CadesErrors.ARCHIVE_TIMESTAMP_CERTIFICATE_INVALID, "Invalid archive timestamp certificate", false));
      }
    }

    X509CertificateKeyUsage certificateKeyUsage = X509CertificateKeyUsage.getInstance(certificate);
    if (!certificateKeyUsage.isExtendedKeyUsageTimestamping()) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.ARCHIVE_TIMESTAMP_CERTIFICATE_MISSING_KEY_USAGE, "Missing timestamping key usage in certificate", false));
    }
  }
}
