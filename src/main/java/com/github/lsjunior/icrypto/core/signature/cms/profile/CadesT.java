package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
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
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public class CadesT extends CadesEpes {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesT() {
    super();
  }

  @Override
  @SuppressWarnings("unchecked")
  protected SignerInformation updateSignerInformation(final CadesSignatureContext context, final CMSSignedData cmsSignedData, final SignerInformation currentSignerInformation) throws Exception {
    if (context.getTimeStampClient() == null) {
      throw new ICryptoException("TimeStamp client is mandatory");
    }

    SignerInformation signerInformation = super.updateSignerInformation(context, cmsSignedData, currentSignerInformation);
    TimeStampProvider ttc = context.getTimeStampClient();

    AttributeTable unsigned = signerInformation.getUnsignedAttributes();
    Hashtable<ASN1ObjectIdentifier, Attribute> hashtable = null;

    if (unsigned == null) {
      hashtable = new Hashtable<>();
    } else {
      hashtable = unsigned.toHashtable();
    }

    byte[] signature = signerInformation.getSignature();
    byte[] timeStamp = ttc.getTimeStamp(Digesters.SHA1.digest(signature), DigestType.SHA1);
    ASN1Primitive asn1Primitive = Asn1Objects.toAsn1Primitive(timeStamp);
    DERSet derSet = new DERSet(asn1Primitive);

    Attribute timeStampAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, derSet);

    hashtable.put(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, timeStampAttribute);

    AttributeTable newUnsignedAtts = new AttributeTable(hashtable);

    return SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAtts);
  }

  @Override
  public void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    super.doVerify(context, signature);
    TimeStamp timeStamp = signature.getSignatureTimeStamp();
    CertPathProvider certPathProvider = context.getCertPathProvider();

    if (timeStamp == null) {
      // CadesA dont require signatureTimeStamp
      if (signature.getArchiveTimeStamp() == null) {
        signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_TIMESTAMP_NOT_FOUND, "Signature timestamp attribute not found", false));
      }
      return;
    }

    byte[] digest = timeStamp.getDigest();
    DigestType digestType = timeStamp.getDigestType();
    Digester digester = Digesters.getDigester(digestType);
    byte[] bytes = digester.digest(signature.getSignature());

    if (!Arrays.equals(digest, bytes)) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_TIMESTAMP_INVALID, "Signature timestamp don't matches signature", false));
    }

    List<Certificate> chain = timeStamp.getChain();
    if ((chain != null) && (!chain.isEmpty())) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_TIMESTAMP_CERTIFICATE_NOT_FOUND, "Signature timestamp certificate not found", false));
      return;
    }

    Certificate certificate = chain.get(0);
    if (certPathProvider != null) {
      try {
        CertPath certPath = certPathProvider.getCertPath(certificate);
        chain = CertPaths.toCertificate(certPath);
      } catch (CertPathBuilderException e) {
        ICryptoLog.getLogger().debug(e.getMessage(), e);
        signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_TIMESTAMP_CERTIFICATE_INVALID, "Invalid signature timestamp certificate", false));
      }
    }

    X509CertificateKeyUsage certificateKeyUsage = X509CertificateKeyUsage.getInstance(certificate);
    if (!certificateKeyUsage.isExtendedKeyUsageTimestamping()) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_TIMESTAMP_CERTIFICATE_MISSING_KEY_USAGE, "Missing timestamping key usage in certificate", false));
    }
  }

}
