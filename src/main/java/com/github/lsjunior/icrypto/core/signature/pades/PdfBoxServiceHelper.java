package com.github.lsjunior.icrypto.core.signature.pades;

import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.graphics.optionalcontent.PDOptionalContentGroup;
import org.apache.pdfbox.pdmodel.graphics.optionalcontent.PDOptionalContentProperties;
import org.apache.pdfbox.pdmodel.graphics.optionalcontent.PDOptionalContentProperties.BaseState;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.ext.icpbrasil.signature.IcpBrasilCommitmentType;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;

public abstract class PdfBoxServiceHelper {

  private PdfBoxServiceHelper() {
    //
  }

  public static boolean isSigned(final ByteSource data) throws IOException {
    if (data == null) {
      return false;
    }

    PDDocument doc = Loader.loadPDF(data.read());
    List<PDSignature> pdSignatureList = doc.getSignatureDictionaries();
    if ((pdSignatureList != null) && (!pdSignatureList.isEmpty())) {
      return true;
    }
    return false;
  }

  public static PDSignature getLastSignature(final PDDocument pdDocument) {
    List<PDSignature> pdSignatureList = pdDocument.getSignatureDictionaries();
    if ((pdSignatureList != null) && (!pdSignatureList.isEmpty())) {
      PDSignature pdSignature = null;
      Date lastDate = null;
      for (PDSignature pdCurrentSignature : pdSignatureList) {
        Date currentDate = pdCurrentSignature.getSignDate().getTime();
        if ((lastDate == null) || (lastDate.before(currentDate))) {
          lastDate = currentDate;
          pdSignature = pdCurrentSignature;
        }
      }
      return pdSignature;
    }
    return null;
  }

  @SuppressWarnings("deprecation")
  public static boolean isLastSignatureMatching(final ByteSource original, final ByteSource signed) throws IOException {
    PDDocument pdDocument = Loader.loadPDF(signed.read());
    PDSignature pdSignature = PdfBoxServiceHelper.getLastSignature(pdDocument);
    COSDictionary dict = pdSignature.getCOSObject();
    COSDictionary digestDictionary = dict.getCOSDictionary(COSName.getPDFName("Digest"));
    if (digestDictionary != null) {

      String sha512 = digestDictionary.getString(COSName.DIGEST_SHA512);
      if (sha512 != null) {
        String originalHash = original.hash(Hashing.sha512()).toString().toLowerCase();
        if (sha512.equalsIgnoreCase(originalHash)) {
          return true;
        }
        return false;
      }

      String sha256 = digestDictionary.getString(COSName.DIGEST_SHA256);
      if (sha256 != null) {
        String originalHash = original.hash(Hashing.sha256()).toString().toLowerCase();
        if (sha256.equalsIgnoreCase(originalHash)) {
          return true;
        }
        return false;
      }

      String sha1 = digestDictionary.getString(COSName.DIGEST_SHA1);
      if (sha1 != null) {
        String originalHash = original.hash(Hashing.sha1()).toString().toLowerCase();
        if (sha1.equalsIgnoreCase(originalHash)) {
          return true;
        }
        return false;
      }
    }
    return false;
  }

  public static int getMDPPermission(final PDDocument document) {
    COSBase base = document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.PERMS);
    if (base instanceof COSDictionary) {
      COSDictionary permsDict = (COSDictionary) base;
      base = permsDict.getDictionaryObject(COSName.DOCMDP);
      if (base instanceof COSDictionary) {
        COSDictionary signatureDict = (COSDictionary) base;
        base = signatureDict.getDictionaryObject("Reference");
        if (base instanceof COSArray) {
          COSArray refArray = (COSArray) base;
          for (int i = 0; i < refArray.size(); ++i) {
            base = refArray.getObject(i);
            if (base instanceof COSDictionary) {
              COSDictionary sigRefDict = (COSDictionary) base;
              if (COSName.DOCMDP.equals(sigRefDict.getDictionaryObject("TransformMethod"))) {
                base = sigRefDict.getDictionaryObject("TransformParams");
                if (base instanceof COSDictionary) {
                  COSDictionary transformDict = (COSDictionary) base;
                  int accessPermissions = transformDict.getInt(COSName.P, 2);
                  if (accessPermissions < 1 || accessPermissions > 3) {
                    accessPermissions = 2;
                  }
                  return accessPermissions;
                }
              }
            }
          }
        }
      }
    }
    return 0;
  }

  public static void setMDPPermission(final PDDocument document, final PDSignature signature, final int accessPermissions) {
    COSDictionary sigDict = signature.getCOSObject();

    COSDictionary transformParameters = new COSDictionary();
    transformParameters.setItem(COSName.TYPE, COSName.getPDFName("TransformParams"));
    transformParameters.setInt(COSName.P, accessPermissions);
    transformParameters.setName(COSName.V, "1.2");
    transformParameters.setNeedToBeUpdated(true);

    COSDictionary referenceDict = new COSDictionary();
    referenceDict.setItem(COSName.TYPE, COSName.getPDFName("SigRef"));
    referenceDict.setItem("TransformMethod", COSName.DOCMDP);
    referenceDict.setItem("DigestMethod", COSName.getPDFName("SHA1"));
    referenceDict.setItem("TransformParams", transformParameters);
    referenceDict.setNeedToBeUpdated(true);

    COSArray referenceArray = new COSArray();
    referenceArray.add(referenceDict);
    sigDict.setItem("Reference", referenceArray);
    referenceArray.setNeedToBeUpdated(true);

    // Catalog
    COSDictionary catalogDict = document.getDocumentCatalog().getCOSObject();
    COSDictionary permsDict = new COSDictionary();
    catalogDict.setItem(COSName.PERMS, permsDict);
    permsDict.setItem(COSName.DOCMDP, signature);
    catalogDict.setNeedToBeUpdated(true);
    permsDict.setNeedToBeUpdated(true);
  }

  public static PDSignature getSignature(final PDDocument document, final String name) {
    PDSignature signature = null;
    PDSignatureField signatureField;
    PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm();
    if (acroForm != null) {
      signatureField = (PDSignatureField) acroForm.getField(name);
      if (signatureField != null) {
        signature = signatureField.getSignature();
        if (signature == null) {
          signature = new PDSignature();
          // after solving PDFBOX-3524
          // signatureField.setValue(signature)
          // until then:
          signatureField.getCOSObject().setItem(COSName.V, signature);
        } else {
          throw new IllegalStateException("The signature field " + name + " is already signed.");
        }
      }
    }
    return signature;
  }

  public static PDVisibleSigProperties getVisibleSigProperties(final File image, final PadesSignatureParameters parameters) throws IOException {
    ByteSource data = parameters.getData();

    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();
    int page = visibleSignature.getPage();
    int left = visibleSignature.getLeft();
    int top = visibleSignature.getTop();
    int width = visibleSignature.getWidth();
    int height = visibleSignature.getHeight();
    int zoom = visibleSignature.getZoom();

    PDVisibleSignDesigner pdVisibleSignDesigner = new PDVisibleSignDesigner(Loader.loadPDF(data.read()), new FileInputStream(image), page);
    pdVisibleSignDesigner.height(height);
    pdVisibleSignDesigner.width(width);
    pdVisibleSignDesigner.xAxis(left);
    pdVisibleSignDesigner.yAxis(top);
    pdVisibleSignDesigner.zoom(zoom);
    pdVisibleSignDesigner.adjustForRotation();

    PDVisibleSigProperties pdVisibleSigProperties = new PDVisibleSigProperties();
    pdVisibleSigProperties.setPdVisibleSignature(pdVisibleSignDesigner);
    pdVisibleSigProperties.page(visibleSignature.getPage());
    pdVisibleSigProperties.preferredSize(0);
    pdVisibleSigProperties.visualSignEnabled(true);

    if (Strings.isNullOrEmpty(parameters.getName())) {
      Identity identity = parameters.getIdentity();
      X509Certificate certificate = (X509Certificate) identity.getChain().get(0);
      pdVisibleSigProperties.signerName(Certificates.toString(certificate.getSubjectX500Principal()));
    } else {
      pdVisibleSigProperties.signerName(parameters.getName());
    }

    if (Strings.isNullOrEmpty(parameters.getName())) {
      pdVisibleSigProperties.signerLocation("Brasília - DF");
    } else {
      pdVisibleSigProperties.signerLocation(parameters.getLocation().getLocalityName());
    }

    if (Strings.isNullOrEmpty(parameters.getReason())) {
      pdVisibleSigProperties.signatureReason(IcpBrasilCommitmentType.CONCORDANCIA.toString());
    } else {
      pdVisibleSigProperties.signatureReason(parameters.getReason());

    }

    pdVisibleSigProperties.buildSignature();
    return pdVisibleSigProperties;
  }

  public static InputStream getVisualSignatureTemplate(final PDDocument document, final File image, final int pageNumber, final PDRectangle rectangle) throws IOException {
    try (PDDocument doc = new PDDocument()) {
      // TODO Add Layer
      String layerName = "iCrypto";
      PDOptionalContentProperties ocprops = document.getDocumentCatalog().getOCProperties();
      if (ocprops == null) {
        ocprops = new PDOptionalContentProperties();
        document.getDocumentCatalog().setOCProperties(ocprops);
      }
      PDOptionalContentGroup layer = null;
      if (ocprops.hasGroup(layerName)) {
        layer = ocprops.getGroup(layerName);
      } else {
        layer = new PDOptionalContentGroup(layerName);
        ocprops.addGroup(layer);
        ocprops.setGroupEnabled(layerName, true);
        ocprops.setBaseState(BaseState.ON);
      }

      PDPage page = new PDPage(document.getPage(pageNumber).getMediaBox());
      doc.addPage(page);
      PDAcroForm acroForm = new PDAcroForm(doc);
      doc.getDocumentCatalog().setAcroForm(acroForm);
      PDSignatureField signatureField = new PDSignatureField(acroForm);
      PDAnnotationWidget widget = signatureField.getWidgets().get(0);
      List<PDField> acroFormFields = acroForm.getFields();
      acroForm.setSignaturesExist(true);
      acroForm.setAppendOnly(true);
      acroForm.getCOSObject().setDirect(true);
      acroFormFields.add(signatureField);

      widget.setRectangle(rectangle);

      // from PDVisualSigBuilder.createHolderForm()
      PDStream stream = new PDStream(document);
      PDRectangle bbox = new PDRectangle(rectangle.getWidth(), rectangle.getHeight());
      Matrix initialScale = null;

      PDResources resources = new PDResources();
      PDFormXObject form = new PDFormXObject(stream);
      form.setFormType(1);
      form.setResources(resources);
      switch (document.getPage(pageNumber).getRotation()) {
        case 90:
          form.setMatrix(AffineTransform.getQuadrantRotateInstance(1));
          initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
          break;
        case 180:
          form.setMatrix(AffineTransform.getQuadrantRotateInstance(2));
          break;
        case 270:
          form.setMatrix(AffineTransform.getQuadrantRotateInstance(3));
          initialScale = Matrix.getScaleInstance(bbox.getWidth() / bbox.getHeight(), bbox.getHeight() / bbox.getWidth());
          break;
        case 0:
        default:
          break;
      }
      form.setBBox(bbox);

      // from PDVisualSigBuilder.createAppearanceDictionary()
      PDAppearanceDictionary appearance = new PDAppearanceDictionary();
      appearance.getCOSObject().setDirect(true);
      PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
      appearance.setNormalAppearance(appearanceStream);
      widget.setAppearance(appearance);

      try (PDPageContentStream cs = new PDPageContentStream(document, appearanceStream)) {
        cs.beginMarkedContent(COSName.OC, layer);
        if (initialScale != null) {
          cs.transform(initialScale);
        }

        cs.addRect(-5000, -5000, 10000, 10000);
        cs.fill();
        cs.saveGraphicsState();

        // Resize Image
        PDImageXObject img = PDImageXObject.createFromFile(image.getAbsolutePath(), document);

        // TODO Calc image
        // cs.transform(Matrix.getScaleInstance(0.1f, 0.1f));
        cs.drawImage(img, 0, 0);
        cs.endMarkedContent();
        cs.close();
      }
      // TODO
      // LayerUtility layerUtility = new LayerUtility(document);
      // layerUtility.appendFormAsLayer(page, form, new AffineTransform(), "Assinatura Digital");

      // no need to set annotations and /P entry

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      doc.save(baos);
      return new ByteArrayInputStream(baos.toByteArray());
    }
  }

  public static PDRectangle getSignatureRectangle(final PDDocument document, final PadesSignatureParameters parameters) {
    VisibleSignatureParameters visibleSignature = parameters.getVisibleSignature();
    int pageNum = visibleSignature.getPage() - 1;
    int left = visibleSignature.getLeft();
    int top = visibleSignature.getTop();
    int width = visibleSignature.getWidth();
    int height = visibleSignature.getHeight();

    Rectangle2D rectangle2d = new Rectangle2D.Float(left, top, width, height);

    float x = (float) rectangle2d.getX();
    float y = (float) rectangle2d.getY();
    PDPage page = document.getPage(pageNum);
    PDRectangle pageRectangle = page.getCropBox();
    PDRectangle pdRectangle = new PDRectangle();
    switch (page.getRotation()) {
      case 90:
        pdRectangle.setLowerLeftY(x);
        pdRectangle.setUpperRightY(x + width);
        pdRectangle.setLowerLeftX(y);
        pdRectangle.setUpperRightX(y + height);
        break;
      case 180:
        pdRectangle.setUpperRightX(pageRectangle.getWidth() - x);
        pdRectangle.setLowerLeftX(pageRectangle.getWidth() - x - width);
        pdRectangle.setLowerLeftY(y);
        pdRectangle.setUpperRightY(y + height);
        break;
      case 270:
        pdRectangle.setLowerLeftY(pageRectangle.getHeight() - x - width);
        pdRectangle.setUpperRightY(pageRectangle.getHeight() - x);
        pdRectangle.setLowerLeftX(pageRectangle.getWidth() - y - height);
        pdRectangle.setUpperRightX(pageRectangle.getWidth() - y);
        break;
      case 0:
      default:
        pdRectangle.setLowerLeftX(x);
        pdRectangle.setUpperRightX(x + width);
        pdRectangle.setLowerLeftY(pageRectangle.getHeight() - y - height);
        pdRectangle.setUpperRightY(pageRectangle.getHeight() - y);
        break;
    }
    return pdRectangle;
  }

  @SuppressWarnings("deprecation")
  public static COSDictionary getSignatureDictionary(final PadesSignatureParameters parameters) {
    COSDictionary dictionary = new COSDictionary();
    dictionary.setItem(COSName.TYPE, COSName.SIG);

    if (!Strings.isNullOrEmpty(parameters.getFilter())) {
      dictionary.setItem(COSName.FILTER, COSName.getPDFName(parameters.getFilter()));
    } else {
      dictionary.setItem(COSName.FILTER, PDSignature.FILTER_ADOBE_PPKLITE);
    }
    if (!Strings.isNullOrEmpty(parameters.getSubFilter())) {
      dictionary.setItem(COSName.SUB_FILTER, COSName.getPDFName(parameters.getSubFilter()));
    } else {
      dictionary.setItem(COSName.SUB_FILTER, PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
    }
    dictionary.setString(COSName.NAME, parameters.getName());
    dictionary.setString(COSName.REASON, parameters.getReason());
    dictionary.setString(COSName.DA, PdfBoxService.DEFAULT_APPEARANCE);
    dictionary.setDate(COSName.M, Calendar.getInstance());
    if (parameters.getLocation() != null) {
      dictionary.setString(COSName.LOCATION, parameters.getLocation().getLocalityName());
    }

    COSDictionary propBuild = new COSDictionary();

    COSDictionary propBuildApp = new COSDictionary();
    propBuildApp.setName(COSName.NAME, "iCrypto");
    propBuildApp.setInt(COSName.R, 100);
    COSArray propBuildAppOs = new COSArray();
    propBuildAppOs.add(COSName.getPDFName(System.getProperty("os.name")));
    propBuildApp.setItem(COSName.OS, propBuildAppOs);
    propBuildApp.setDirect(true);
    propBuild.setItem(COSName.APP, propBuildApp);

    COSDictionary propBuildFilter = new COSDictionary();
    propBuildFilter.setItem(COSName.NAME, PDSignature.FILTER_ADOBE_PPKLITE);
    propBuildFilter.setDate(COSName.DATE, Calendar.getInstance());
    propBuildFilter.setDirect(true);
    propBuild.setItem(COSName.FILTER, propBuildFilter);
    propBuild.setDirect(true);

    dictionary.setItem(COSName.PROP_BUILD, propBuild);

    try {
      String sha1 = parameters.getData().hash(Hashing.sha1()).toString().toLowerCase();
      String sha256 = parameters.getData().hash(Hashing.sha256()).toString().toLowerCase();
      String sha512 = parameters.getData().hash(Hashing.sha512()).toString().toLowerCase();

      COSDictionary hash = new COSDictionary();
      hash.setString(COSName.DIGEST_SHA1, sha1);
      hash.setString(COSName.DIGEST_SHA256, sha256);
      hash.setString(COSName.DIGEST_SHA512, sha512);
      dictionary.setItem(COSName.getPDFName("Digest"), hash);
    } catch (IOException e) {
      ICryptoLog.getLogger().warn(e.getMessage(), e);
    }

    return dictionary;
  }

  public static COSStream toStream(final Map<String, COSStream> streams, final byte[] data) throws IOException {
    byte[] hash = Hashing.sha256().hashBytes(data).asBytes();
    String hex = BaseEncoding.base16().encode(hash);
    COSStream stream = streams.get(hex);

    if (stream == null) {
      stream = new COSStream();
      COSArray filters = new COSArray();
      filters.add(COSName.FLATE_DECODE);
      try (OutputStream filteredStream = stream.createOutputStream(filters)) {
        filteredStream.write(data);
        filteredStream.flush();
      }
      streams.put(hex, stream);
    }

    return stream;
  }

}
