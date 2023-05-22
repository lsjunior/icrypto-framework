package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.esf.CrlListID;
import org.bouncycastle.asn1.esf.CrlOcspRef;
import org.bouncycastle.asn1.esf.CrlValidatedID;
import org.bouncycastle.asn1.esf.OcspListID;
import org.bouncycastle.asn1.esf.OcspResponsesID;
import org.bouncycastle.asn1.esf.OtherHash;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.api.model.CertificateRevocationData;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.model.Signature;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.digest.Digester;
import com.github.lsjunior.icrypto.core.digest.util.Digesters;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesServiceHelper;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.google.common.collect.Iterables;

public class CadesXl extends CadesX {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesXl() {
    super();
  }

  @Override
  @SuppressWarnings("unchecked")
  protected SignerInformation updateSignerInformation(final CadesSignatureContext context, final CMSSignedData cmsSignedData, final SignerInformation currentSignerInformation) throws Exception {
    SignerInformation signerInformation = super.updateSignerInformation(context, cmsSignedData, currentSignerInformation);
    List<Certificate> chain = context.getChain();
    Map<Certificate, CertificateRevocationData> revocations = context.getRevocations();

    List<org.bouncycastle.asn1.x509.Certificate> certificateList = new ArrayList<>();

    for (int i = 0; i < chain.size(); i++) {
      Certificate certificate = chain.get(i);

      CertificateRevocationData revocationData = revocations.get(certificate);

      CRL crl = revocationData.getCrl();
      byte[] ocspBytes = revocationData.getOcsp();

      if ((i == 0) && (crl == null) && (ocspBytes == null)) {
        X509Certificate x509Certificate = (X509Certificate) certificate;
        throw new IllegalStateException("CRL/OCSP not found for " + Certificates.toString(x509Certificate.getSubjectX500Principal()));
      }

      if (i > 0) {
        org.bouncycastle.asn1.x509.Certificate c = org.bouncycastle.asn1.x509.Certificate.getInstance((certificate.getEncoded()));
        certificateList.add(c);
      }
    }

    RevocationValues revocationValues = CadesServiceHelper.toRevocationValues(chain, revocations, true);

    DERSequence certValues = new DERSequence(Iterables.toArray(certificateList, org.bouncycastle.asn1.x509.Certificate.class));

    Attribute revogarionAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_revocationValues, new DERSet(revocationValues));
    Attribute certAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_certValues, new DERSet(certValues));

    // Update content
    AttributeTable unsigned = signerInformation.getUnsignedAttributes();
    Hashtable<ASN1ObjectIdentifier, Attribute> hashtable = new Hashtable<>();

    if (unsigned == null) {
      hashtable = new Hashtable<>();
    } else {
      hashtable = unsigned.toHashtable();
    }

    // Refs
    hashtable.put(PKCSObjectIdentifiers.id_aa_ets_revocationValues, revogarionAttribute);
    hashtable.put(PKCSObjectIdentifiers.id_aa_ets_certValues, certAttribute);
    // TODO OCSPObjectIdentifiers.id_pkix_ocsp_basic
    // TODO CMSObjectIdentifiers.id_ri_ocsp_response

    AttributeTable newUnsignedAtts = new AttributeTable(hashtable);

    return SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAtts);
  }

  @Override
  public void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    super.doVerify(context, signature);

    this.verifyCertificate(signature);
    this.verifyRevocation(signature);
  }

  private void verifyCertificate(final Signature signature) throws IOException {
    byte[] certificateValuesBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certValues.getId());
    if (certificateValuesBytes == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_VALUES_NOT_FOUND, "Certificate values attribute not found", false));
      return;
    }

    byte[] certificateRefsBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId());
    if (certificateRefsBytes == null) {
      return;
    }

    Attribute certificateValuesAttribute = Attribute.getInstance(certificateValuesBytes);
    ASN1Set certificateValuesValue = certificateValuesAttribute.getAttrValues();
    ASN1Sequence certificateValuesSequence = ASN1Sequence.getInstance(certificateValuesValue.getObjectAt(0));

    Attribute certificateRefsAttribute = Attribute.getInstance(certificateRefsBytes);
    ASN1Set certificateRefsValue = certificateRefsAttribute.getAttrValues();
    ASN1Sequence certificateRefsSequence = ASN1Sequence.getInstance(certificateRefsValue.getObjectAt(0));

    for (int certificateValueIndex = 0; certificateValueIndex < certificateValuesSequence.size(); certificateValueIndex++) {
      ASN1Encodable certificateEncodable = certificateValuesSequence.getObjectAt(certificateValueIndex);
      org.bouncycastle.asn1.x509.Certificate certificate = org.bouncycastle.asn1.x509.Certificate.getInstance(certificateEncodable);

      boolean error = true;
      for (int certificateRefIndex = 0; certificateRefIndex < certificateRefsSequence.size(); certificateRefIndex++) {
        ASN1Encodable encodable = certificateRefsSequence.getObjectAt(certificateRefIndex);
        OtherCertID otherCertID = OtherCertID.getInstance(encodable);
        AlgorithmIdentifier algorithmIdentifier = otherCertID.getAlgorithmHash();
        DigestType digestType = Asn1Objects.getDigestType(algorithmIdentifier);
        Digester digester = Digesters.getDigester(digestType);
        BigInteger serialNumber = certificate.getSerialNumber().getPositiveValue();
        X500Name issuerName = certificate.getIssuer();

        IssuerSerial issuerSerial = otherCertID.getIssuerSerial();
        if (issuerSerial != null) {
          GeneralNames generalNames = issuerSerial.getIssuer();
          X500Name x500Name = Certificates.toX500Name(generalNames);
          ASN1Integer asn1Integer = issuerSerial.getSerial();
          BigInteger bigInteger = asn1Integer != null ? asn1Integer.getPositiveValue() : null;

          if ((Objects.equals(issuerName, x500Name)) && (Objects.equals(serialNumber, bigInteger))) {
            byte[] certificateHash = digester.digest(certificate.getEncoded());

            if (!Arrays.equals(otherCertID.getCertHash(), certificateHash)) {
              String msg = String.format("Certificate %s ref not matches reference hash", Certificates.toString(certificate.getSubject()));
              signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_HASH_NOT_MATCHES, msg, true));
            } else {
              error = false;
            }
          }
        }
      }

      if (error) {
        String msg = String.format("Reference to certificate %s not found", Certificates.toString(certificate.getSubject()));
        signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_REF_NOT_FOUND, msg, false));
      }
    }

  }

  private void verifyRevocation(final Signature signature) throws ParseException, IOException {
    byte[] certificateValuesBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationValues.getId());
    if (certificateValuesBytes == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.REVOCATION_VALUES_NOT_FOUND, "Revocation values attribute not found", false));
      return;
    }

    byte[] certificateRefsBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId());
    if (certificateRefsBytes == null) {
      return;
    }

    Attribute revocationValuesAttribute = Attribute.getInstance(certificateValuesBytes);
    ASN1Set revocationValuesValue = revocationValuesAttribute.getAttrValues();
    RevocationValues revocationValues = RevocationValues.getInstance(revocationValuesValue.getObjectAt(0));

    Attribute revocationRefsAttribute = Attribute.getInstance(certificateRefsBytes);
    ASN1Set revocationRefsValue = revocationRefsAttribute.getAttrValues();
    ASN1Sequence revocationRefsSequence = ASN1Sequence.getInstance(revocationRefsValue.getObjectAt(0));

    CertificateList[] certificateLists = revocationValues.getCrlVals();
    BasicOCSPResponse[] ocspResponses = revocationValues.getOcspVals();
    for (CertificateList certificateList : certificateLists) {
      boolean error = true;
      for (int sequenceRefIndex = 0; sequenceRefIndex < revocationRefsSequence.size(); sequenceRefIndex++) {
        ASN1Encodable encodable = revocationRefsSequence.getObjectAt(sequenceRefIndex);
        CrlOcspRef crlOcspRef = CrlOcspRef.getInstance(encodable);
        CrlListID crlListID = crlOcspRef.getCrlids();
        if (crlListID != null) {
          CrlValidatedID[] crlValidatedIDs = crlListID.getCrls();
          if (crlValidatedIDs != null) {
            for (CrlValidatedID crlValidatedID : crlValidatedIDs) {
              if (this.isEquals(certificateList, crlValidatedID)) {
                error = false;
                break;
              }
            }
          }
        }
      }
      if (error) {
        String msg = String.format("Reference to CRL issued by %s not found", Certificates.toString(certificateList.getIssuer()));
        signature.getErrors().add(new ErrorMessage(CadesErrors.CRL_REF_NOT_FOUND, msg, false));
      }
    }

    for (BasicOCSPResponse basicOcspResponse : ocspResponses) {
      boolean error = true;
      for (int sequenceRefIndex = 0; sequenceRefIndex < revocationRefsSequence.size(); sequenceRefIndex++) {
        ASN1Encodable encodable = revocationRefsSequence.getObjectAt(sequenceRefIndex);
        CrlOcspRef crlOcspRef = CrlOcspRef.getInstance(encodable);
        OcspListID ocspListID = crlOcspRef.getOcspids();
        if (ocspListID != null) {
          OcspResponsesID[] ocspResponsesIDs = ocspListID.getOcspResponses();
          if (ocspResponsesIDs != null) {
            for (OcspResponsesID ocspResponsesID : ocspResponsesIDs) {
              if (this.isEquals(basicOcspResponse, ocspResponsesID)) {
                error = false;
                break;
              }
            }
          }
        }
      }
      if (error) {
        String responderName = Certificates.toString(basicOcspResponse.getTbsResponseData().getResponderID().getName());
        String msg = String.format("Reference to OCSP issued by %s not found", responderName);
        signature.getErrors().add(new ErrorMessage(CadesErrors.OCSP_REF_NOT_FOUND, msg, false));
      }
    }
  }

  private boolean isEquals(final CertificateList certificateList, final CrlValidatedID crlValidatedID) throws ParseException, IOException {
    if ((certificateList == null) || (crlValidatedID == null)) {
      return false;
    }

    X500Name name1 = certificateList.getIssuer();
    X500Name name2 = crlValidatedID.getCrlIdentifier().getCrlIssuer();
    // RockFrameworkLogger.getLogger().info(String.format("Check CRL %s x %s", n1, n2));
    if (Objects.equals(name1, name2)) {
      return false;
    }

    Date date1 = Asn1Objects.toDate(certificateList.getThisUpdate());
    Date date2 = Asn1Objects.toDate(crlValidatedID.getCrlIdentifier().getCrlIssuedTime());
    if (Objects.equals(date1, date2)) {
      return false;
    }

    byte[] encoded = certificateList.getEncoded();
    byte[] hash = crlValidatedID.getCrlHash().getHashValue();

    OtherHash otherHash = crlValidatedID.getCrlHash();
    DigestType digestType = null;
    if (otherHash != null) {
      AlgorithmIdentifier algorithmIdentifier = otherHash.getHashAlgorithm();
      digestType = Asn1Objects.getDigestType(algorithmIdentifier);

    } else {
      digestType = DigestType.SHA1;
    }

    Digester digester = Digesters.getDigester(digestType);
    byte[] calculatedHash = digester.digest(encoded);
    if (!Arrays.equals(calculatedHash, hash)) {
      return false;
    }

    return true;
  }

  private boolean isEquals(final BasicOCSPResponse basicOcspResponse, final OcspResponsesID ocspResponsesId) throws ParseException, IOException {
    if ((basicOcspResponse == null) || (ocspResponsesId == null)) {
      return false;
    }

    ResponderID responder1 = basicOcspResponse.getTbsResponseData().getResponderID();
    ResponderID responder2 = ocspResponsesId.getOcspIdentifier().getOcspResponderID();
    X500Name name1 = responder1.getName();
    X500Name name2 = responder2.getName();
    // RockFrameworkLogger.getLogger().info(String.format("Check OCSP %s x %s", n1, n2));
    if (Objects.equals(name1, name2)) {
      return false;
    }

    byte[] keyHash1 = responder1.getKeyHash();
    byte[] keyHash2 = responder2.getKeyHash();

    if (keyHash1 != null) {
      if (keyHash2 == null) {
        return false;
      }
      if (!Arrays.equals(keyHash1, keyHash2)) {
        return false;
      }
    } else if (keyHash2 != null) {
      return false;
    }

    Date date1 = Asn1Objects.toDate(basicOcspResponse.getTbsResponseData().getProducedAt());
    Date date2 = Asn1Objects.toDate(ocspResponsesId.getOcspIdentifier().getProducedAt());
    if (Objects.equals(date1, date2)) {
      return false;
    }

    BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOcspResponse);
    byte[] encodec = basicOcspResp.getEncoded();
    byte[] hash = ocspResponsesId.getOcspRepHash().getHashValue();
    OtherHash otherHash = ocspResponsesId.getOcspRepHash();
    DigestType digestType = null;
    if (otherHash != null) {
      AlgorithmIdentifier algorithmIdentifier = otherHash.getHashAlgorithm();
      digestType = Asn1Objects.getDigestType(algorithmIdentifier);

    } else {
      digestType = DigestType.SHA1;
    }

    Digester digester = Digesters.getDigester(digestType);
    byte[] calculatedHash = digester.digest(encodec);
    if (!Arrays.equals(calculatedHash, hash)) {
      return false;
    }

    return true;
  }
}
