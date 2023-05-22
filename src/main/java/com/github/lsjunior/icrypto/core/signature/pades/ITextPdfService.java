package com.github.lsjunior.icrypto.core.signature.pades;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.util.Store;
import org.xml.sax.SAXException;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.signature.cms.CadesSignature;
import com.google.common.base.Strings;
import com.google.common.collect.Iterables;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.html.simpleparser.HTMLWorker;
import com.lowagie.text.html.simpleparser.StyleSheet;
import com.lowagie.text.pdf.ColumnText;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfTemplate;
import com.lowagie.text.pdf.PdfWriter;

public class ITextPdfService extends AbstractPadesService implements Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private static final ITextPdfService INSTANCE = new ITextPdfService();

  public ITextPdfService() {
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
      stp = PdfStamper.createSignature(reader, outputStream, '\0', null, true);
    } catch (DocumentException e) {
      ICryptoLog.getLogger().info(e.getMessage(), e);
      reader.close();
      reader = new PdfReader(inputFile.getAbsolutePath());
      stp = PdfStamper.createSignature(reader, outputStream, '\0', null, false);
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
      PdfStamper stamper = new PdfStamper(reader, outputStream, '\0', true);
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
    // TODO Fazer a implementaca usando apenas o OpenPDF
    return PdfBoxService.getInstance().verify(parameters);
  }

  public static ITextPdfService getInstance() {
    return ITextPdfService.INSTANCE;
  }

}
