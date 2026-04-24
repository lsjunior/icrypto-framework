package com.github.lsjunior.icrypto.core.signature.pades;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.StringReader;
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
import org.openpdf.text.DocumentException;
import org.openpdf.text.Image;
import org.openpdf.text.Rectangle;
import org.openpdf.text.html.simpleparser.HTMLWorker;
import org.openpdf.text.html.simpleparser.StyleSheet;
import org.openpdf.text.pdf.AcroFields;
import org.openpdf.text.pdf.ColumnText;
import org.openpdf.text.pdf.PdfArray;
import org.openpdf.text.pdf.PdfDate;
import org.openpdf.text.pdf.PdfDictionary;
import org.openpdf.text.pdf.PdfName;
import org.openpdf.text.pdf.PdfNumber;
import org.openpdf.text.pdf.PdfObject;
import org.openpdf.text.pdf.PdfReader;
import org.openpdf.text.pdf.PdfSignatureAppearance;
import org.openpdf.text.pdf.PdfStamper;
import org.openpdf.text.pdf.PdfString;
import org.openpdf.text.pdf.PdfTemplate;
import org.openpdf.text.pdf.PdfWriter;
import org.xml.sax.SAXException;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.model.Document;
import com.github.lsjunior.icrypto.api.model.ErrorMessage;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;
import com.github.lsjunior.icrypto.core.signature.cms.CadesService;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignature;
import com.github.lsjunior.icrypto.core.signature.cms.CadesVerificationParameters;
import com.github.lsjunior.icrypto.core.signature.cms.CadesVerificationResult;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.github.lsjunior.icrypto.core.util.Dates;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;

public class OpenPdfService extends AbstractPadesService implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final OpenPdfService INSTANCE = new OpenPdfService();

  public OpenPdfService() {
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

  protected PadesSignature doSign(final PadesSignatureParameters parameters) throws IOException, SAXException {
    ByteSource data = parameters.getData();

    File inputFile = File.createTempFile("pades-service", ".pdf");
    File outputFile = File.createTempFile("pades-service", ".pdf");
    Files.asByteSink(inputFile).writeFrom(data.openStream());
    OutputStream outputStream = new FileOutputStream(outputFile);
    Calendar calendar = Calendar.getInstance();

    // PdfReader reader = new PdfReader(data.openStream());
    PdfReader reader = new PdfReader(inputFile.getAbsolutePath());
    PdfStamper stp = null;
    try {
      stp = PdfStamper.createSignature(reader, outputStream, "\u0000", null, true);
    } catch (DocumentException e) {
      ICryptoLog.getLogger().info(e.getMessage(), e);
      reader.close();
      reader = new PdfReader(inputFile.getAbsolutePath());
      stp = PdfStamper.createSignature(reader, outputStream, "\u0000", null, false);
    }
    stp.setIncludeFileID(true);
    stp.setEnforcedModificationDate(calendar);

    // Evita os PDFs/A de causarem erro na validacao
    ITextPdfServiceHelper.handleXmpModifyDate(stp, calendar);

    if (!this.isSigned(reader)) {
      stp.setOverrideFileId(ITextPdfServiceHelper.generateFileId());
    }

    PdfSignatureAppearance sap = stp.getSignatureAppearance();
    sap.setAcro6Layers(true);

    PdfDictionary cryptoDictionary = ITextPdfServiceHelper.getCryptoDictionary(parameters, inputFile);

    // Causa erro nas assinaturas multiplas
    // if (!this.isSigned(reader)) {
    // sap.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);
    // }

    sap.setCryptoDictionary(cryptoDictionary);

    if (parameters.getVisibleSignature() != null) {
      if (!Strings.isNullOrEmpty(parameters.getVisibleSignature().getTemplate())) {
        this.addVisibleSignature(sap, parameters);
      } else {
        BufferedImage image = this.getSignatureImage(parameters);
        this.addVisibleSignature(sap, parameters, image);
      }
    } else if (!Strings.isNullOrEmpty(parameters.getSignatureFieldName())) {
      this.addVisibleSignatureOnField(sap, parameters);
    }

    CadesSignatureAdapter adapter = new CadesSignatureAdapter(parameters);
    int extraSize = adapter.doPreSign();
    int csize = 8192 * 4 + extraSize;
    byte[] outc = new byte[csize];

    HashMap<PdfName, Integer> exc = new HashMap<>();
    exc.put(PdfName.CONTENTS, Integer.valueOf(csize * 2 + 2));
    // exc.put(new PdfName("DSS"), Integer.valueOf(csize));
    // exc.put(PdfName.EXTENSIONS, Integer.valueOf(1024));
    // exc.put(PdfName.VERSION, Integer.valueOf(1024));

    sap.preClose(exc);

    InputStream rangeStream = sap.getRangeStream();

    CadesSignature cadesSignature = adapter.doSign(rangeStream);

    byte[] cms = cadesSignature.getData().read();

    // Add cms data
    // PdfDictionary sigDic = ITextPdfServiceHelper.getDocumentDictionary(cms);
    PdfDictionary sigDic = new PdfDictionary();

    System.arraycopy(cms, 0, outc, 0, cms.length);

    sigDic.put(PdfName.CONTENTS, new PdfString(outc).setHexWriting(true));
    sap.close(sigDic);

    // outputFile = this.updateDss(outputFile, cms);

    PadesSignature result = new PadesSignature();
    result.setAlgorithm(cadesSignature.getAlgorithm());
    result.setCertificate(cadesSignature.getCertificate());
    result.setChain(cadesSignature.getChain());
    result.setData(Files.asByteSource(outputFile));
    return result;
  }

  @SuppressWarnings("deprecation")
  protected File updateDss(final File file, final byte[] cms) throws IOException, CMSException {
    // TODO
    // DSS OK???
    // Extensions OK
    // Metadata OK
    // Version

    File outputFile = File.createTempFile("pades-service", ".pdf");

    try (PdfReader reader = new PdfReader(file.getAbsolutePath()); OutputStream outputStream = new FileOutputStream(outputFile)) {
      PdfDictionary catalog = reader.getCatalog();
      PdfStamper stamper = new PdfStamper(reader, outputStream, "\u0000", true);
      PdfWriter writer = stamper.getWriter();

      PdfDictionary dss = new PdfDictionary();
      dss.put(PdfName.TYPE, new PdfName("DSS"));

      Map<String, PdfObject> streams = new HashMap<>();

      Set<X509CertificateHolder> allCertificates = new HashSet<>();
      Set<X509CRLHolder> allCrls = new HashSet<>();
      Set<BasicOCSPResponse> allOcsps = new HashSet<>();

      PdfDictionary vriDictionary = new PdfDictionary();
      vriDictionary.put(PdfName.TYPE, new PdfName("VRI"));
      // TODO CRL, Cert, OCSP, TU
      // PBAD_PolicyArtifacts, PBAD_LpaArtifacts, PBAD_LpaSignatures

      byte[] digest = Hashing.sha1().hashBytes(cms).asBytes();
      String hexHash = BaseEncoding.base16().encode(digest).toUpperCase();

      PdfDictionary sigVriDictionary = new PdfDictionary();

      // ExtensoesPAsPAdES 2.16.76.1.8.0
      // br-ext-mandatedPdfSigDicEntries 2.16.76.1.8.1
      // br-ext-dss 2.16.76.1.8.2
      // br-ext-mandatedDocTSEntries 2.16.76.1.8.3

      vriDictionary.put(new PdfName(hexHash), sigVriDictionary);

      CMSSignedData cmsSignedData = new CMSSignedData(cms);
      Store<X509CertificateHolder> certificates = cmsSignedData.getCertificates();
      Store<X509CRLHolder> crls = cmsSignedData.getCRLs();
      Store<?> ocsps = cmsSignedData.getOtherRevocationInfo(PKCSObjectIdentifiers.id_aa_ets_revocationValues);

      if (certificates != null) {
        PdfArray vriCertArray = new PdfArray();
        for (X509CertificateHolder certificate : certificates.getMatches(null)) {
          vriCertArray.add(ITextPdfServiceHelper.toStream(writer, streams, certificate.getEncoded()));
          allCertificates.add(certificate);
        }
        if (vriCertArray.size() > 0) {
          sigVriDictionary.put(PdfName.CERT, vriCertArray);
        }
      }

      if (crls != null) {
        PdfArray vriCrlArray = new PdfArray();
        for (X509CRLHolder crl : crls.getMatches(null)) {
          vriCrlArray.add(ITextPdfServiceHelper.toStream(writer, streams, crl.getEncoded()));
          allCrls.add(crl);
        }
        if (vriCrlArray.size() > 0) {
          sigVriDictionary.put(new PdfName("CRL"), vriCrlArray);
        }
      }

      // FIXME
      if (ocsps != null) {
        PdfArray vriOcspArray = new PdfArray();
        for (Object ocsp : ocsps.getMatches(null)) {
          RevocationValues revocationValues = (RevocationValues) ocsp;
          BasicOCSPResponse[] responses = revocationValues.getOcspVals();
          for (BasicOCSPResponse response : responses) {
            vriOcspArray.add(ITextPdfServiceHelper.toStream(writer, streams, response.getEncoded()));
            allOcsps.add(response);
          }
        }
      }

      if (!allCertificates.isEmpty()) {
        PdfArray arrayAllCerts = new PdfArray();
        for (X509CertificateHolder certificate : allCertificates) {
          arrayAllCerts.add(ITextPdfServiceHelper.toStream(writer, streams, certificate.getEncoded()));
        }
        dss.put(new PdfName("Certs"), arrayAllCerts);
        vriDictionary.put(new PdfName("Cert"), arrayAllCerts);
      }

      if (!allCrls.isEmpty()) {
        PdfArray arrayAllCrls = new PdfArray();
        for (X509CRLHolder crl : allCrls) {
          arrayAllCrls.add(ITextPdfServiceHelper.toStream(writer, streams, crl.getEncoded()));
        }
        dss.put(new PdfName("CRLs"), arrayAllCrls);
      }

      if (!allOcsps.isEmpty()) {
        PdfArray arrayAllOcsps = new PdfArray();
        for (BasicOCSPResponse ocsp : allOcsps) {
          arrayAllOcsps.add(ITextPdfServiceHelper.toStream(writer, streams, ocsp.getEncoded()));
        }
        dss.put(new PdfName("OCSPs"), arrayAllOcsps);
        vriDictionary.put(new PdfName("OCSP"), arrayAllOcsps);
      }

      dss.put(new PdfName("VRI"), writer.addToBody(vriDictionary, false).getIndirectReference());

      catalog.put(new PdfName("DSS"), writer.addToBody(dss, false).getIndirectReference());

      PdfDictionary extentionsAdbe = new PdfDictionary();
      extentionsAdbe.put(PdfName.BASEVERSION, new PdfString("1.7"));
      extentionsAdbe.put(PdfName.EXTENSIONLEVEL, new PdfNumber(5));

      PdfDictionary extentions = new PdfDictionary();
      extentions.put(PdfName.ADBE, extentionsAdbe);
      catalog.put(PdfName.EXTENSIONS, writer.addToBody(extentions).getIndirectReference());

      catalog.put(PdfName.VERSION, new PdfString("1.7"));

      stamper.getWriter().addToBody(reader.getCatalog(), reader.getCatalog().getIndRef(), false);
      stamper.close();

      return outputFile;
    }
  }

  private void addVisibleSignature(final PdfSignatureAppearance appearance, final PadesSignatureParameters parameters, final BufferedImage image) throws IOException {
    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();
    int page = visibleSignature.getPage();
    int zoom = visibleSignature.getZoom();
    int width = visibleSignature.getWidth();
    int height = visibleSignature.getHeight();

    if (width == 0) {
      width = image.getWidth();
    }
    if (height == 0) {
      height = image.getHeight();
    }
    if (zoom > 0) {
      width *= ((float) zoom / 100);
      height *= ((float) zoom / 100);
    }

    Rectangle rect = this.getSignatureRectangle(appearance, parameters, image);
    rect.setBackgroundColor(Color.BLACK);
    appearance.setVisibleSignature(rect, page);

    PdfTemplate layer = appearance.getLayer(2);
    ColumnText ct = new ColumnText(layer);
    ct.addElement(Image.getInstance(image, null));
    ct.setSimpleColumn(0, 0, width, height);
    ct.go();
  }

  private void addVisibleSignature(final PdfSignatureAppearance appearance, final PadesSignatureParameters parameters) throws IOException {
    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();
    int page = visibleSignature.getPage();
    int zoom = visibleSignature.getZoom();
    int width = visibleSignature.getWidth();
    int height = visibleSignature.getHeight();

    if (zoom > 0) {
      width *= ((float) zoom / 100);
      height *= ((float) zoom / 100);
    }

    Rectangle rect = this.getSignatureRectangle(appearance, parameters, null);
    rect.setBackgroundColor(Color.WHITE);
    appearance.setVisibleSignature(rect, page);

    final String html = this.getSignatureHtml(parameters);
    final StyleSheet style = new StyleSheet();

    // ol ul li a pre font span br p div body table td th tr i b u sub sup em strong s strike h1 h2 h3 h4 h5 h6 img h
    PdfTemplate layer = appearance.getLayer(2);
    ColumnText ct = new ColumnText(layer);
    ct.addElement(HTMLWorker.parseToList(new StringReader(html), style).get(0));
    ct.setSimpleColumn(0, 0, width, height);
    ct.go();
  }

  private void addVisibleSignatureOnField(final PdfSignatureAppearance appearance, final PadesSignatureParameters parameters) {
    appearance.setCrypto(parameters.getIdentity().getPrivateKey(), Iterables.toArray(parameters.getIdentity().getChain(), Certificate.class), null, null);
    appearance.setRender(PdfSignatureAppearance.SignatureRenderNameAndDescription);
    appearance.setVisibleSignature(parameters.getSignatureFieldName());

    // appearance.setLayer2Font(iTextFont);
    // appearance.setLayer2Text();

    Rectangle rect = appearance.getRect();
    if (rect != null) {
      // width = (int) rect.getWidth();
      // height = (int) rect.getHeight();
    }
  }

  private Rectangle getSignatureRectangle(final PdfSignatureAppearance appearance, final PadesSignatureParameters parameters, final BufferedImage image) {
    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();

    int page = visibleSignature.getPage();
    int left = visibleSignature.getLeft();
    int top = visibleSignature.getTop();
    int zoom = visibleSignature.getZoom();
    int width = visibleSignature.getWidth();
    int height = visibleSignature.getHeight();

    if ((width == 0) && (image != null)) {
      width = image.getWidth();
    }
    if ((height == 0) && (image != null)) {
      height = image.getHeight();
    }
    if (zoom > 0) {
      width *= ((float) zoom / 100);
      height *= ((float) zoom / 100);
    }

    PdfReader reader = appearance.getStamper().getReader();
    Rectangle pageSize = reader.getPageSizeWithRotation(page);
    PdfArray mediabox = reader.getPageN(page).getAsArray(PdfName.MEDIABOX);
    PdfArray cropbox = reader.getPageN(page).getAsArray(PdfName.CROPBOX);

    float originX = pageSize.getWidth();
    float originY = pageSize.getHeight();
    if (cropbox != null) {
      float cx = cropbox.getAsNumber(1).floatValue();
      float cy = cropbox.getAsNumber(2).floatValue();
      if (cx < 0) {
        originX = cx;
        left = ((int) originX) + left;
      }
      if (cy < 0) {
        // FIXME Talvez precise fazer a mesma coisa do left...
        originY = cy;
      }
    } else if (mediabox != null) {
      float cx = mediabox.getAsNumber(1).floatValue();
      float cy = mediabox.getAsNumber(2).floatValue();
      if (cx < 0) {
        originX = cx;
        left = ((int) originX) + left;
      }
      if (cy < 0) {
        // FIXME Talvez precise fazer a mesma coisa do left...
        originY = cy;
      }
    }

    Rectangle rect = new Rectangle(left, originY - top - height, left + width, originY - top);
    return rect;
  }

  private boolean isSigned(final PdfReader reader) {
    return ITextPdfServiceHelper.isSigned(reader);
  }

  @Override
  public PadesVerificationResult verify(final PadesVerificationParameters parameters) {
    try {
      return this.doVerify(parameters);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  public PadesVerificationResult doVerify(final PadesVerificationParameters parameters) throws IOException {
    ByteSource signature = parameters.getSignature();
    if (signature == null) {
      throw new ICryptoException("PDF is empty");
    }

    byte[] pdfBytes = signature.read();
    try (PdfReader reader = new PdfReader(pdfBytes)) {
      AcroFields acroFields = reader.getAcroFields();
      List<String> signatureNames = acroFields != null ? acroFields.getSignedFieldNames() : Collections.emptyList();
      if ((signatureNames != null) && (!signatureNames.isEmpty())) {
        PadesVerificationResult padesResult = new PadesVerificationResult();
        padesResult.setDocument(new Document());
        padesResult.getDocument().setCertificates(new ArrayList<>());
        padesResult.getDocument().setContent(signature);
        padesResult.getDocument().setCrls(new ArrayList<>());
        padesResult.getDocument().setErrors(new ArrayList<>());
        padesResult.getDocument().setSignatures(new ArrayList<>());

        for (String signatureName : signatureNames) {
          try {
            PdfDictionary signatureDictionary = acroFields.getSignatureDictionary(signatureName);
            String filter = this.getPdfNameValue(signatureDictionary.getAsName(PdfName.FILTER));
            String subFilter = this.getPdfNameValue(signatureDictionary.getAsName(PdfName.SUBFILTER));

            if ("Adobe.PPKLite".equals(filter)) {
              PadesVerificationResult tmpResult = null;
              if ("ETSI.CAdES.detached".equals(subFilter) || "adbe.pkcs7.detached".equals(subFilter)) {
                tmpResult = this.doVerifyEtsi(parameters, signature, signatureDictionary, pdfBytes);
              } else if ("adbe.pkcs7.sha1".equals(subFilter)) {
                tmpResult = this.doVerifyPkcs7Sha1(parameters, signatureDictionary);
              } else if ("adbe.x509.rsa_sha1".equals(subFilter)) {
                tmpResult = this.doVerifyX509Sha1(signature, signatureDictionary, pdfBytes);
              } else {
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

  protected PadesVerificationResult doVerifyEtsi(final PadesVerificationParameters parameters, final ByteSource signature, final PdfDictionary signatureDictionary,
      final byte[] pdfBytes) throws IOException {
    byte[] signatureBytes = this.getSignatureBytes(signatureDictionary);
    byte[] signedContent = this.getSignedContent(signatureDictionary, pdfBytes);
    CadesService cadesService = CadesService.getInstance();
    CadesVerificationParameters verificationParameters = new CadesVerificationParameters();
    verificationParameters.setData(ByteSource.wrap(signedContent));
    verificationParameters.setSignature(ByteSource.wrap(signatureBytes));
    verificationParameters.setCertPathProvider(parameters.getCertPathProvider());
    verificationParameters.setChain(parameters.getChain());
    verificationParameters.setSignaturePolicyProvider(parameters.getSignaturePolicyProvider());
    verificationParameters.setSignatureProfile(parameters.getSignatureProfile());

    CadesVerificationResult cadesResult = cadesService.verify(verificationParameters);
    PadesVerificationResult padesResult = new PadesVerificationResult();
    padesResult.setDocument(cadesResult.getDocument());
    padesResult.setValid(cadesResult.isValid());

    if ((padesResult.getDocument() != null) && (padesResult.getDocument().getSignatures() != null)) {
      Calendar signDate = this.getSignDate(signatureDictionary);
      if (signDate != null) {
        for (com.github.lsjunior.icrypto.api.model.Signature s : padesResult.getDocument().getSignatures()) {
          if (s.getSigningTime() == null) {
            s.setSigningTime(Dates.toLocalDateTime(signDate.getTime()));
          }
        }
      }
    }
    return padesResult;
  }

  protected PadesVerificationResult doVerifyPkcs7Sha1(final PadesVerificationParameters parameters, final PdfDictionary signatureDictionary) throws IOException {
    byte[] signature = this.getSignatureBytes(signatureDictionary);
    CadesService cadesService = CadesService.getInstance();
    CadesVerificationParameters verificationParameters = new CadesVerificationParameters();
    verificationParameters.setData(ByteSource.wrap(signature));
    verificationParameters.setSignature(ByteSource.wrap(signature));
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
  protected PadesVerificationResult doVerifyX509Sha1(final ByteSource data, final PdfDictionary signatureDictionary, final byte[] pdfBytes)
      throws IOException, GeneralSecurityException {
    byte[] signature = this.getSignatureBytes(signatureDictionary);
    PdfArray certsArray = signatureDictionary.getAsArray(PdfName.CERT);
    List<Certificate> certificates = new ArrayList<>();
    if (certsArray != null) {
      for (PdfObject base : certsArray.getElements()) {
        PdfString certStr = (PdfString) base;
        X509Certificate certificate = (X509Certificate) Certificates.toCertificate(certStr.getBytes());
        certificates.add(certificate);
      }
    }

    byte[] signedContent = this.getSignedContent(signatureDictionary, pdfBytes);

    ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(signature));
    byte[] pkcs1SigValue = ((DEROctetString) in.readObject()).getOctets();
    in.close();

    com.github.lsjunior.icrypto.api.model.Signature signatureModel = new com.github.lsjunior.icrypto.api.model.Signature();
    signatureModel.setChain(certificates);
    signatureModel.setSignatureType(SignatureType.SHA1_RSA);
    Calendar signDate = this.getSignDate(signatureDictionary);
    if (signDate != null) {
      signatureModel.setSigningTime(Dates.toLocalDateTime(signDate.getTime()));
    }
    signatureModel.setMessageDigest(Hashing.sha1().hashBytes(signedContent).toString().toUpperCase());
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

  private byte[] getSignatureBytes(final PdfDictionary signatureDictionary) {
    PdfString contents = signatureDictionary.getAsString(PdfName.CONTENTS);
    if (contents == null) {
      throw new ICryptoException("PDF signature contents not found");
    }
    return contents.getBytes();
  }

  private byte[] getSignedContent(final PdfDictionary signatureDictionary, final byte[] pdfBytes) throws IOException {
    PdfArray byteRange = signatureDictionary.getAsArray(PdfName.BYTERANGE);
    if ((byteRange == null) || (byteRange.size() < 4)) {
      throw new ICryptoException("PDF signature ByteRange not found");
    }

    ByteArrayOutputStream output = new ByteArrayOutputStream();
    for (int i = 0; i + 1 < byteRange.size(); i += 2) {
      PdfNumber offsetNumber = byteRange.getAsNumber(i);
      PdfNumber lengthNumber = byteRange.getAsNumber(i + 1);
      if ((offsetNumber == null) || (lengthNumber == null)) {
        continue;
      }

      int offset = offsetNumber.intValue();
      int length = lengthNumber.intValue();
      if ((offset < 0) || (length < 0) || (offset + length > pdfBytes.length)) {
        throw new ICryptoException("Invalid PDF signature ByteRange");
      }

      output.write(pdfBytes, offset, length);
    }
    return output.toByteArray();
  }

  private Calendar getSignDate(final PdfDictionary signatureDictionary) {
    PdfString signDate = signatureDictionary.getAsString(PdfName.M);
    if (signDate == null) {
      return null;
    }
    try {
      return PdfDate.decode(signDate.toString());
    } catch (Exception e) {
      ICryptoLog.getLogger().debug(e.getMessage(), e);
      return null;
    }
  }

  private String getPdfNameValue(final PdfName pdfName) {
    if (pdfName == null) {
      return null;
    }
    String value = pdfName.toString();
    if ((value != null) && value.startsWith("/")) {
      return value.substring(1);
    }
    return value;
  }

  public static OpenPdfService getInstance() {
    return OpenPdfService.INSTANCE;
  }

}
