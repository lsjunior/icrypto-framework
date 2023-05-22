package com.github.lsjunior.icrypto.core.signature.cms.profile;

import java.math.BigInteger;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.bouncycastle.asn1.ess.OtherCertID;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
import com.github.lsjunior.icrypto.api.type.RevokeReasonType;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.CrlProvider;
import com.github.lsjunior.icrypto.core.digest.Digester;
import com.github.lsjunior.icrypto.core.digest.util.Digesters;
import com.github.lsjunior.icrypto.core.ocsp.OcspProvider;
import com.github.lsjunior.icrypto.core.ocsp.util.Ocsps;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesServiceHelper;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignatureContext;
import com.github.lsjunior.icrypto.core.signature.cms.VerificationContext;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.google.common.collect.Iterables;

public class CadesC extends CadesT {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public CadesC() {
    super();
  }

  @SuppressWarnings("unchecked")
  @Override
  protected SignerInformation updateSignerInformation(final CadesSignatureContext context, final CMSSignedData cmsSignedData, final SignerInformation currentSignerInformation) throws Exception {
    List<Certificate> chain = context.getChain();
    CrlProvider crlProvider = context.getCrlProvider();
    OcspProvider ocspProvider = context.getOcspProvider();

    DigestType digestType = context.getSignatureType().getDigestType();

    SignerInformation signerInformation = super.updateSignerInformation(context, cmsSignedData, currentSignerInformation);

    List<OtherCertID> otherCertIds = new ArrayList<>();
    List<CrlOcspRef> crlOcspRefs = new ArrayList<>();

    Map<Certificate, CertificateRevocationData> revocations = context.getRevocations();
    if (revocations == null) {
      revocations = CadesServiceHelper.getCrlAndOcsps(chain, crlProvider, ocspProvider);
      context.setRevocations(revocations);
    }

    for (int i = 0; i < chain.size(); i++) {
      Certificate certificate = chain.get(i);

      Certificate issuer = null;
      if ((i + 1) < chain.size()) {
        issuer = chain.get(i + 1);
      } else {
        issuer = certificate;
      }

      if (i > 0) {
        OtherCertID otherCertId = CadesServiceHelper.toOtherCertID(certificate, issuer, digestType);
        otherCertIds.add(otherCertId);
      }

      CertificateRevocationData revocationData = revocations.get(certificate);

      CRL crl = revocationData != null ? revocationData.getCrl() : null;
      byte[] ocspBytes = revocationData != null ? revocationData.getOcsp() : null;

      if ((i == 0) && (crl == null) && (ocspBytes == null)) {
        X509Certificate x509Certificate = (X509Certificate) certificate;
        throw new IllegalStateException("CRL/OCSP not found for " + Certificates.toString(x509Certificate.getSubjectX500Principal()));
      }

      List<CrlValidatedID> crlIds = new ArrayList<>();
      List<OcspResponsesID> ocspIds = new ArrayList<>();

      if (crl != null) {
        if (crl.isRevoked(certificate)) {
          throw new IllegalStateException("Certificate is revoked");
        }

        CrlValidatedID crlId = CadesServiceHelper.toCrlValidatedID(crl, digestType);
        crlIds.add(crlId);
      }

      if (ocspBytes != null) {
        BasicOCSPResponse basicOcspResponse = BasicOCSPResponse.getInstance(ocspBytes);
        BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOcspResponse);

        RevokeReasonType revokeReason = Ocsps.isRevoked(basicOcspResp);
        if (revokeReason != null) {
          throw new IllegalStateException("Certificate is revoked with status " + revokeReason.toString());
        }

        OcspResponsesID ocspId = CadesServiceHelper.toOcspResponsesID(basicOcspResp, digestType);
        ocspIds.add(ocspId);
      }

      CrlListID crlListId = new CrlListID(Iterables.toArray(crlIds, CrlValidatedID.class));
      OcspListID ocspListId = new OcspListID(Iterables.toArray(ocspIds, OcspResponsesID.class));

      CrlOcspRef crlOcspRef = new CrlOcspRef(crlListId, ocspListId, null);
      crlOcspRefs.add(crlOcspRef);
    }

    OtherCertID[] certIdsArray = Iterables.toArray(otherCertIds, OtherCertID.class);
    CrlOcspRef[] refsArray = Iterables.toArray(crlOcspRefs, CrlOcspRef.class);

    Attribute certIdsAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_certificateRefs, new DERSet(new DERSequence(certIdsArray)));
    Attribute refsAttribute = new Attribute(PKCSObjectIdentifiers.id_aa_ets_revocationRefs, new DERSet(new DERSequence(refsArray)));

    // Update content
    AttributeTable unsigned = signerInformation.getUnsignedAttributes();
    Hashtable<ASN1ObjectIdentifier, Attribute> hashtable = unsigned.toHashtable();

    // Refs
    hashtable.put(PKCSObjectIdentifiers.id_aa_ets_certificateRefs, certIdsAttribute);
    hashtable.put(PKCSObjectIdentifiers.id_aa_ets_revocationRefs, refsAttribute);

    AttributeTable newUnsignedAtts = new AttributeTable(hashtable);

    return SignerInformation.replaceUnsignedAttributes(signerInformation, newUnsignedAtts);
  }

  @Override
  public void doVerify(final VerificationContext context, final Signature signature) throws Exception {
    super.doVerify(context, signature);

    this.verifyCertificate(signature);
    this.verifyRevocation(signature);
  }

  private void verifyCertificate(final Signature signature) throws CertificateEncodingException {
    byte[] certificateBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_certificateRefs.getId());

    if (certificateBytes == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_REFS_NOT_FOUND, "Certificate refs attribute not found", false));
      return;
    }

    Attribute attribute = Attribute.getInstance(certificateBytes);
    ASN1Set derSet = attribute.getAttrValues();
    ASN1Sequence asn1Sequence = ASN1Sequence.getInstance(derSet.getObjectAt(0));

    List<Certificate> chain = signature.getChain();
    for (int chainIndex = 1; chainIndex < chain.size(); chainIndex++) {
      X509Certificate x509Certificate = (X509Certificate) chain.get(chainIndex);
      boolean error = true;
      for (int sequenceIndex = 0; sequenceIndex < asn1Sequence.size(); sequenceIndex++) {
        ASN1Encodable encodable = asn1Sequence.getObjectAt(sequenceIndex);
        OtherCertID otherCertId = OtherCertID.getInstance(encodable);
        AlgorithmIdentifier algorithmIdentifier = otherCertId.getAlgorithmHash();
        DigestType digestType = Asn1Objects.getDigestType(algorithmIdentifier);
        Digester digester = Digesters.getDigester(digestType);
        BigInteger serialNumber = x509Certificate.getSerialNumber();
        X500Name issuerName = Certificates.toX500Name(x509Certificate.getIssuerX500Principal());

        IssuerSerial issuerSerial = otherCertId.getIssuerSerial();
        if (issuerSerial != null) {
          GeneralNames generalNames = issuerSerial.getIssuer();
          X500Name x500Name = Certificates.toX500Name(generalNames);
          ASN1Integer asn1Integer = issuerSerial.getSerial();
          BigInteger bigInteger = asn1Integer != null ? asn1Integer.getPositiveValue() : null;

          if ((Objects.equals(issuerName, x500Name)) && (Objects.equals(serialNumber, bigInteger))) {
            byte[] certificateHash = digester.digest(x509Certificate.getEncoded());

            if (!Arrays.equals(otherCertId.getCertHash(), certificateHash)) {
              String msg = String.format("Certificate %s ref not matches reference hash", Certificates.toString(x509Certificate.getSubjectX500Principal()));
              signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_HASH_NOT_MATCHES, msg, true));
            } else {
              error = false;
            }
          }
        }

      }

      if (error) {
        String msg = String.format("Reference to certificate %s not found", Certificates.toString(x509Certificate.getSubjectX500Principal()));
        signature.getErrors().add(new ErrorMessage(CadesErrors.CERTIFICATE_REF_NOT_FOUND, msg, false));
      }
    }

  }

  private void verifyRevocation(final Signature signature) {
    byte[] revocationBytes = signature.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_revocationRefs.getId());

    if (revocationBytes == null) {
      signature.getErrors().add(new ErrorMessage(CadesErrors.REVOCATION_REFS_NOT_FOUND, "Revocation refs attribute not found", false));
    }
  }

}
