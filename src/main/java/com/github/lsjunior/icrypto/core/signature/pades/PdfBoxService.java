package com.github.lsjunior.icrypto.core.signature.pades;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.imageio.ImageIO;
import javax.xml.transform.TransformerException;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.InvalidPasswordException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.xmpbox.XMPMetadata;
import org.apache.xmpbox.schema.XMPBasicSchema;
import org.apache.xmpbox.xml.XmpSerializer;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.Document;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesService;
import com.github.lsjunior.icrypto.core.signature.cms.CadesVerificationParameters;
import com.github.lsjunior.icrypto.core.signature.cms.CadesVerificationResult;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;

public class PdfBoxService extends AbstractPadesService implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final PdfBoxService INSTANCE = new PdfBoxService();

  public static final String DEFAULT_APPEARANCE = "/Helv 0 Tf 0 g";

  protected PdfBoxService() {
    super();
  }

  @Override
  public PadesSignature sign(final PadesSignatureParameters parameters) {
    try {
      return this.doSign(parameters);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected PadesSignature doSign(final PadesSignatureParameters parameters) throws IOException, CMSException, TransformerException {
    ByteSource data = parameters.getData();

    File outputFile = File.createTempFile("pdfbox-service", ".pdf");

    PDDocument document = Loader.loadPDF(data.read());

    int accessPermissions = PdfBoxServiceHelper.getMDPPermission(document);
    if (accessPermissions == 1) {
      throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
    }

    PDAcroForm form = document.getDocumentCatalog().getAcroForm();
    if (form != null && form.getNeedAppearances()) {
      // PDFBOX-3738
      if (form.getFields().isEmpty()) {
        form.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
      }
    }

    // COSDictionary dictionary = doc.getDocumentCatalog().getCOSObject();

    CadesSignatureInterface signatureInterface = new CadesSignatureInterface(parameters);
    int extraSize = signatureInterface.preSign();
    SignatureOptions signatureOptions = new SignatureOptions();
    signatureOptions.setPreferredSignatureSize((SignatureOptions.DEFAULT_SIGNATURE_SIZE * 4) + extraSize);

    if ((parameters.getVisibleSignature() != null)) {
      BufferedImage image = this.getSignatureImage(parameters);
      File imageFile = File.createTempFile("pdfbox-service-img", ".png");
      ImageIO.write(image, "PNG", imageFile);
      int imageSize = (int) Files.asByteSource(imageFile).size();
      int page = parameters.getVisibleSignature().getPage();
      signatureOptions.setPreferredSignatureSize(signatureOptions.getPreferredSignatureSize() + imageSize);

      boolean basic = true;
      if (basic) {
        PDVisibleSigProperties pdVisibleSigProperties = PdfBoxServiceHelper.getVisibleSigProperties(imageFile, parameters);
        signatureOptions.setPage(page - 1);
        signatureOptions.setVisualSignature(pdVisibleSigProperties);
      } else {
        PDRectangle pdRectangle = PdfBoxServiceHelper.getSignatureRectangle(document, parameters);
        InputStream visualSignature = PdfBoxServiceHelper.getVisualSignatureTemplate(document, imageFile, page - 1, pdRectangle);
        signatureOptions.setVisualSignature(visualSignature);
      }
    }

    PDSignature signature = new PDSignature(PdfBoxServiceHelper.getSignatureDictionary(parameters));
    // PDSignature signature = new PDSignature();
    // signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
    // signature.setName(parameters.getName());
    // signature.setReason(parameters.getReason());
    // signature.setSignDate(Calendar.getInstance());
    // signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

    // if (parameters.getLocation() != null) {
    // signature.setLocation(parameters.getLocation().getLocalityName());
    // }

    if ((document.getVersion() >= 1.5f) && (accessPermissions == 0)) {
      PdfBoxServiceHelper.setMDPPermission(document, signature, 1);
    }

    boolean external = true;
    if (external) {
      File fileTmp = File.createTempFile("pdfbox-service-tmp", ".pdf");
      FileOutputStream outputStreamTmp = new FileOutputStream(fileTmp);
      // document.save(outputStreamTmp);
      // outputStreamTmp.close();
      // outputStreamTmp = new FileOutputStream(fileTmp);

      document.addSignature(signature, signatureInterface, signatureOptions);
      document.setDocumentId(Long.valueOf(System.currentTimeMillis()));

      ExternalSigningSupport externalSigning = document.saveIncrementalForExternalSigning(outputStreamTmp);

      byte[] cms = signatureInterface.sign(externalSigning.getContent());
      externalSigning.setSignature(cms);

      outputFile = fileTmp;

      PDDocument signed = Loader.loadPDF(fileTmp);
      this.updateDocumentDictionary(signed, cms);
      FileOutputStream outputStream = new FileOutputStream(outputFile);
      signed.saveIncremental(outputStream);
      outputStream.close();
      signatureOptions.close();

      /*
       * if (fileTmp.exists()) { fileTmp.delete(); }
       */
    } else {
      document.addSignature(signature, signatureInterface, signatureOptions);
      FileOutputStream outputStream = new FileOutputStream(outputFile);
      document.saveIncremental(outputStream);
      outputStream.close();
    }

    PadesSignature result = new PadesSignature();
    result.setAlgorithm(signatureInterface.getSignature().getAlgorithm());
    result.setCertificate(signatureInterface.getSignature().getCertificate());
    result.setChain(signatureInterface.getSignature().getChain());
    result.setData(Files.asByteSource(outputFile));

    return result;
  }

  @SuppressWarnings("deprecation")
  protected void updateDocumentDictionary(final PDDocument document, final byte[] cms) throws IOException, CMSException, TransformerException {
    // TODO
    // DSS OK???
    // Extensions OK
    // Metadata OK
    // Version

    PDMetadata metadata = document.getDocumentCatalog().getMetadata();
    if (metadata == null) {
      XMPMetadata xmp = XMPMetadata.createXMPMetadata();
      XMPBasicSchema dc = xmp.createAndAddXMPBasicSchema();
      // dc.setDescription("iCrypto");
      dc.setModifyDate(Calendar.getInstance());
      XmpSerializer serializer = new XmpSerializer();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      serializer.serialize(xmp, baos, true);

      metadata = new PDMetadata(document);
      metadata.importXMPMetadata(baos.toByteArray());
      document.getDocumentCatalog().setMetadata(metadata);
    }

    COSDictionary dictionary = document.getDocumentCatalog().getCOSObject();

    COSDictionary dss = new COSDictionary();
    dss.setItem(COSName.TYPE, COSName.getPDFName("DSS"));

    Map<String, COSStream> streams = new HashMap<>();

    Set<X509CertificateHolder> allCertificates = new HashSet<>();
    Set<X509CRLHolder> allCrls = new HashSet<>();
    Set<BasicOCSPResponse> allOcsps = new HashSet<>();

    COSDictionary vriDictionary = new COSDictionary();
    vriDictionary.setItem(COSName.TYPE, COSName.getPDFName("VRI"));
    // TODO CRL, Cert, OCSP, TU
    // PBAD_PolicyArtifacts, PBAD_LpaArtifacts, PBAD_LpaSignatures

    byte[] digest = Hashing.sha1().hashBytes(cms).asBytes();
    String hexHash = BaseEncoding.base16().encode(digest).toUpperCase();

    COSDictionary sigVriDictionary = new COSDictionary();

    // ExtensoesPAsPAdES 2.16.76.1.8.0
    // br-ext-mandatedPdfSigDicEntries 2.16.76.1.8.1
    // br-ext-dss 2.16.76.1.8.2
    // br-ext-mandatedDocTSEntries 2.16.76.1.8.3

    vriDictionary.setItem(hexHash, sigVriDictionary);

    CMSSignedData cmsSignedData = new CMSSignedData(cms);
    Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();
    Store<X509CRLHolder> crls = cmsSignedData.getCRLs();
    Store<?> ocsps = cmsSignedData.getOtherRevocationInfo(PKCSObjectIdentifiers.id_aa_ets_revocationValues);

    if (certificates != null) {
      COSArray vriCertArray = new COSArray();
      for (X509CertificateHolder certificate : certificates.getMatches(null)) {
        vriCertArray.add(PdfBoxServiceHelper.toStream(streams, certificate.getEncoded()));
        allCertificates.add(certificate);
      }
      if (vriCertArray.size() > 0) {
        vriDictionary.setItem("Cert", new COSObject(vriCertArray));
      }
    }

    if (crls != null) {
      COSArray vriCrlArray = new COSArray();
      for (X509CRLHolder crl : crls.getMatches(null)) {
        vriCrlArray.add(PdfBoxServiceHelper.toStream(streams, crl.getEncoded()));
        allCrls.add(crl);
      }
      if (vriCrlArray.size() > 0) {
        vriDictionary.setItem("CRL", new COSObject(vriCrlArray));
      }
    }

    // FIXME
    if (ocsps != null) {
      COSArray vriOcspArray = new COSArray();
      for (Object ocsp : ocsps.getMatches(null)) {
        RevocationValues revocationValues = (RevocationValues) ocsp;
        BasicOCSPResponse[] responses = revocationValues.getOcspVals();
        for (BasicOCSPResponse response : responses) {
          vriOcspArray.add(PdfBoxServiceHelper.toStream(streams, response.getEncoded()));
          allOcsps.add(response);
        }
      }
    }

    if (!allCertificates.isEmpty()) {
      COSArray arrayAllCerts = new COSArray();
      for (X509CertificateHolder certificate : allCertificates) {
        arrayAllCerts.add(PdfBoxServiceHelper.toStream(streams, certificate.getEncoded()));
      }
      dss.setItem("Certs", new COSObject(arrayAllCerts));
    }

    if (!allCrls.isEmpty()) {
      COSArray arrayAllCrls = new COSArray();
      for (X509CRLHolder crl : allCrls) {
        arrayAllCrls.add(PdfBoxServiceHelper.toStream(streams, crl.getEncoded()));
      }
      dss.setItem("CRLs", new COSObject(arrayAllCrls));
    }

    if (!allOcsps.isEmpty()) {
      COSArray arrayAllOcsps = new COSArray();
      for (BasicOCSPResponse ocsp : allOcsps) {
        arrayAllOcsps.add(PdfBoxServiceHelper.toStream(streams, ocsp.getEncoded()));
      }
      dss.setItem("OCSPs", new COSObject(arrayAllOcsps));
      vriDictionary.setItem("OCSP", new COSObject(arrayAllOcsps));
    }

    dss.setItem("VRI", vriDictionary);

    dictionary.setItem("DSS", dss);

    COSDictionary extentions = new COSDictionary();
    COSDictionary extentionsAdbe = new COSDictionary();
    extentionsAdbe.setName(COSName.getPDFName("BaseVersion"), "1.7");
    extentionsAdbe.setInt("ExtensionLevel", 5);
    extentionsAdbe.setDirect(true);
    extentions.setItem(COSName.getPDFName("ADBE"), extentionsAdbe);
    extentions.setDirect(true);
    // TODO Extensão br_ext_dss br_ext_mandatedDocTSEntries
    dictionary.setItem("Extensions", extentions);

    dictionary.setName(COSName.VERSION, "1.7");

    dictionary.setNeedToBeUpdated(true);
  }

  @Override
  public PadesVerificationResult verify(final PadesVerificationParameters parameters) {
    try {
      return this.doVerify(parameters);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public PadesVerificationResult doVerify(final PadesVerificationParameters parameters) throws InvalidPasswordException, IOException {
    // ByteSource data = parameters.getData();
    ByteSource signature = parameters.getSignature();
    if (signature == null) {
      throw new ICryptoException("PDF is empty");
    }

    try (PDDocument doc = Loader.loadPDF(signature.read())) {
      List<PDSignature> pdSignatureList = doc.getSignatureDictionaries();
      if ((pdSignatureList != null) && (!pdSignatureList.isEmpty())) {
        PadesVerificationResult padesResult = new PadesVerificationResult();
        padesResult.setDocument(new Document());
        padesResult.getDocument().setCertificates(new ArrayList<>());
        padesResult.getDocument().setContent(signature);
        padesResult.getDocument().setCrls(new ArrayList<>());
        padesResult.getDocument().setErrors(new ArrayList<>());
        padesResult.getDocument().setSignatures(new ArrayList<>());

        for (PDSignature pdSignature : pdSignatureList) {
          try {
            String filter = pdSignature.getFilter();
            String subFilter = pdSignature.getSubFilter();
            if (PDSignature.FILTER_ADOBE_PPKLITE.getName().equals(filter)) {
              PadesVerificationResult tmpResult = null;
              if ((PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName().equals(subFilter)) || (PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED.getName().equals(subFilter))) {
                tmpResult = this.doVerifyEtsi(parameters, signature, pdSignature);
              } else if ((PDSignature.SUBFILTER_ADBE_PKCS7_SHA1.getName().equals(subFilter))) {
                tmpResult = this.doVerifyPkcs7Sha1(parameters, signature, pdSignature);
              } else if ((PDSignature.SUBFILTER_ADBE_X509_RSA_SHA1.getName().equals(subFilter))) {
                tmpResult = this.doVerifyX509Sha1(signature, pdSignature);
              } else {
                // ETSI.RFC3161 https://www.etsi.org/deliver/etsi_ts/102700_102799/10277804/01.01.02_60/ts_10277804v010102p.pdf
                String msg = String.format("Invalid PDF Signature SubFilter '%s'", subFilter);
                com.github.lsjunior.icrypto.api.model.Signature tmpSignature = this.getErrorSignature(filter, subFilter, PadesErrors.SUBFILTER_INVALID, msg);
                padesResult.getDocument().getSignatures().add(tmpSignature);
              }

              if (tmpResult != null) {
                for (com.github.lsjunior.icrypto.api.model.Signature s : tmpResult.getDocument().getSignatures()) {
                  s.setFilter(filter);
                  s.setSubFilter(subFilter);
                }
                padesResult.getDocument().getSignatures().addAll(tmpResult.getDocument().getSignatures());
              }
            } else {
              String msg = String.format("Invalid PDF Signature Filter '%s'", filter);
              com.github.lsjunior.icrypto.api.model.Signature tmpSignature = this.getErrorSignature(filter, subFilter, PadesErrors.FILTER_INVALID, msg);
              padesResult.getDocument().getSignatures().add(tmpSignature);
            }
          } catch (Exception e) {
            ICryptoLog.getLogger().warn(e.getMessage(), e);
            padesResult.getDocument().getErrors().add(new ErrorMessage(PadesErrors.UNCAUGHT_ERROR, e.getMessage(), true));
          }
        }

        boolean valid = true;
        for (com.github.lsjunior.icrypto.api.model.Signature s : padesResult.getDocument().getSignatures()) {
          for (ErrorMessage e : s.getErrors()) {
            if (e.isFatal()) {
              valid = false;
              break;
            }
          }
        }
        padesResult.setValid(valid);

        return padesResult;
      }
      return null;
    }
  }

  private com.github.lsjunior.icrypto.api.model.Signature getErrorSignature(final String filter, final String subFilter, final int errorCode, final String errorMsg) {
    com.github.lsjunior.icrypto.api.model.Signature s = new com.github.lsjunior.icrypto.api.model.Signature();
    s.setErrors(new ArrayList<>());
    s.getErrors().add(new ErrorMessage(errorCode, errorMsg, true));
    s.setFilter(filter);
    s.setSubFilter(subFilter);
    return s;
  }

  protected PadesVerificationResult doVerifyEtsi(final PadesVerificationParameters parameters, final ByteSource signature, final PDSignature pdSignature) throws IOException {
    COSDictionary dict = pdSignature.getCOSObject();
    COSString contents = (COSString) dict.getDictionaryObject(COSName.CONTENTS);
    byte[] signatureBytes = contents.getBytes();
    byte[] signedContent = pdSignature.getSignedContent(signature.openStream());
    CadesService cadesService = CadesService.getInstance();
    CadesVerificationParameters verificationParameters = new CadesVerificationParameters();
    verificationParameters.setData(ByteSource.wrap(signedContent));
    verificationParameters.setSignature(ByteSource.wrap(signatureBytes));
    // Clone...
    verificationParameters.setCertPathProvider(parameters.getCertPathProvider());
    verificationParameters.setChain(parameters.getChain());
    verificationParameters.setSignaturePolicyProvider(parameters.getSignaturePolicyProvider());
    verificationParameters.setSignatureProfile(parameters.getSignatureProfile());

    CadesVerificationResult cadesResult = cadesService.verify(verificationParameters);
    PadesVerificationResult padesResult = new PadesVerificationResult();
    padesResult.setDocument(cadesResult.getDocument());
    padesResult.setValid(cadesResult.isValid());

    if ((padesResult.getDocument() != null) && (padesResult.getDocument().getSignatures() != null)) {
      Calendar signDate = pdSignature.getSignDate();
      if (signDate != null) {
        for (com.github.lsjunior.icrypto.api.model.Signature s : padesResult.getDocument().getSignatures()) {
          if (s.getSigningTime() == null) {
            s.setSigningTime(signDate.getTime());
          }
        }
      }
    }
    return padesResult;
  }

  protected PadesVerificationResult doVerifyPkcs7Sha1(final PadesVerificationParameters parameters, final ByteSource data, final PDSignature pdSignature) throws IOException {
    byte[] signature = pdSignature.getContents(data.openStream());
    CadesService cadesService = CadesService.getInstance();
    CadesVerificationParameters verificationParameters = new CadesVerificationParameters();
    verificationParameters.setData(ByteSource.wrap(signature));
    verificationParameters.setSignature(ByteSource.wrap(signature));
    // Clone...
    verificationParameters.setCertPathProvider(parameters.getCertPathProvider());
    verificationParameters.setChain(parameters.getChain());
    verificationParameters.setSignaturePolicyProvider(parameters.getSignaturePolicyProvider());
    verificationParameters.setSignatureProfile(parameters.getSignatureProfile());

    CadesVerificationResult cadesResult = cadesService.verify(verificationParameters);
    PadesVerificationResult padesResult = new PadesVerificationResult();
    padesResult.setDocument(cadesResult.getDocument());
    padesResult.setValid(cadesResult.isValid());
    return padesResult;
  }

  @SuppressWarnings("deprecation")
  protected PadesVerificationResult doVerifyX509Sha1(final ByteSource data, final PDSignature pdSignature) throws IOException, GeneralSecurityException {
    COSDictionary dict = pdSignature.getCOSObject();
    COSString contents = (COSString) dict.getDictionaryObject(COSName.CONTENTS);
    COSArray certsArray = (COSArray) dict.getDictionaryObject(COSName.CERT);
    List<Certificate> certificates = new ArrayList<>();
    for (COSBase base : certsArray) {
      COSString certStr = (COSString) base;
      X509Certificate certificate = (X509Certificate) Certificates.toCertificate(certStr.getBytes());
      certificates.add(certificate);
      // ICryptoLog.getLogger().info("Certificate " + certificate.getSubjectX500Principal());
    }

    byte[] signature = contents.getBytes();
    byte[] signedContent = pdSignature.getSignedContent(data.openStream()); // Conteudo que foi assinado

    ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(signature));
    byte[] pkcs1SigValue = ((DEROctetString) in.readObject()).getOctets();
    in.close();

    // Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", BcProvider.PROVIDER_NAME);
    // c.init(Cipher.DECRYPT_MODE, certificates.get(0));
    // byte[] raw = c.doFinal(pkcs1SigValue);
    // ASN1Sequence sequence = ASN1Sequence.getInstance(raw);
    // DigestInfo digestInfo = DigestInfo.getInstance(sequence);
    // byte[] digest = digestInfo.getDigest();
    // keyAndParameterAlgorithm = ID_RSA;

    com.github.lsjunior.icrypto.api.model.Signature signatureModel = new com.github.lsjunior.icrypto.api.model.Signature();
    signatureModel.setChain(certificates);
    signatureModel.setSignatureType(SignatureType.SHA1_RSA);
    signatureModel.setSigningTime(pdSignature.getSignDate().getTime());
    signatureModel.setMessageDigest(Hashing.sha1().hashBytes(signedContent).toString().toUpperCase());
    // signatureModel.setMessageDigest(BaseEncoding.base16().encode(signedContent));
    signatureModel.setErrors(new ArrayList<>());
    signatureModel.getErrors().add(new ErrorMessage(PadesErrors.FORMAT_INSECURE, "Insecure signature filter/subfilter (adbe.x509.rsa_sha1)", false));
    signatureModel.getErrors().add(new ErrorMessage(PadesErrors.ALGORITHM_INSECURE, "Insecure signature algorithm (SHA1)", false));

    Document documentModel = new Document();
    documentModel.setContent(data);
    documentModel.setSignatures(Collections.singletonList(signatureModel));

    PadesVerificationResult result = new PadesVerificationResult();
    result.setDocument(documentModel);

    Signature sig = Signature.getInstance(SignatureType.SHA1_RSA.getAlgorithm(), BcProvider.PROVIDER_NAME);
    sig.initVerify(certificates.get(0));
    sig.update(signedContent);

    if (sig.verify(pkcs1SigValue)) {
      // OK
    } else {
      signatureModel.getErrors().add(new ErrorMessage(CadesErrors.SIGNATURE_INVALID, "Signature Inválid", true));
    }
    return result;
  }

  public static PdfBoxService getInstance() {
    return PdfBoxService.INSTANCE;
  }

}
