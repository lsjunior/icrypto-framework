package com.github.lsjunior.icrypto.core.timestamp.util;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.api.model.TimeStamp;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;

public abstract class TimeStamps {

  private TimeStamps() {
    //
  }

  public static TimeStamp toTimeStamp(final byte[] bytes) throws IOException, TSPException, CMSException, GeneralSecurityException {
    TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(bytes));
    TimeStamp timeStamp = TimeStamps.toTimeStamp(timeStampToken);
    return timeStamp;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  public static TimeStamp toTimeStamp(final TimeStampToken timeStampToken) throws IOException, GeneralSecurityException {
    if (timeStampToken == null) {
      return null;
    }

    TimeStampTokenInfo timeStampTokenInfo = timeStampToken.getTimeStampInfo();

    TimeStamp timeStamp = new TimeStamp();
    timeStamp.setDate(timeStampTokenInfo.getGenTime());
    timeStamp.setDigest(timeStampTokenInfo.getMessageImprintDigest());
    timeStamp.setEncoded(timeStampToken.getEncoded());
    timeStamp.setNonce(timeStampTokenInfo.getNonce());
    timeStamp.setSerialNumber(timeStampTokenInfo.getSerialNumber());

    ASN1ObjectIdentifier digestAlgId = timeStampTokenInfo.getMessageImprintAlgOID();
    if (digestAlgId != null) {
      timeStamp.setDigestType(Asn1Objects.getDigestType(digestAlgId));
    }

    ASN1ObjectIdentifier policyId = timeStampTokenInfo.getPolicy();
    if (policyId != null) {
      timeStamp.setPolicyId(policyId.getId());
    }

    CMSSignedData signedData = timeStampToken.toCMSSignedData();

    Object signedContent = signedData.getSignedContent().getContent();
    if ((signedContent != null) && (signedContent.getClass().isArray())) {
      timeStamp.setContent((byte[]) signedContent);
    }

    SignerInformation signerInformation = signedData.getSignerInfos().get(timeStampToken.getSID());
    SignatureType signatureType = Asn1Objects.getSignatureType(signerInformation.getDigestAlgOID(), signerInformation.getEncryptionAlgOID());
    timeStamp.setSignature(signerInformation.getSignature());
    timeStamp.setSignatureType(signatureType);

    SignerId signerId = timeStampToken.getSID();
    Store certificatesStore = timeStampToken.getCertificates();
    Collection<X509CertificateHolder> certificateMatches = certificatesStore.getMatches(signerId);
    X509CertificateHolder certificateHolder = null;

    List<Certificate> chain = null;
    if ((certificateMatches != null) && (!certificateMatches.isEmpty())) {
      certificateHolder = certificateMatches.iterator().next();
    }

    if (certificateHolder != null) {
      Collection<X509CertificateHolder> allMatches = certificatesStore.getMatches(null);
      if (allMatches.size() > 1) {
        chain = Certificates.getChain(certificateHolder, allMatches);
      } else {
        chain = Collections.singletonList(Certificates.toCertificate(certificateHolder));
      }
    }
    timeStamp.setChain(chain);

    return timeStamp;
  }

}
