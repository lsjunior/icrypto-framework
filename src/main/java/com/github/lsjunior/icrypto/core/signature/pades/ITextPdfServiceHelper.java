package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.util.BcProvider;
import com.google.common.base.Strings;
import com.google.common.hash.Hashing;
import com.google.common.io.BaseEncoding;
import com.google.common.io.ByteSource;
import com.google.common.io.Files;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.ByteBuffer;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfDate;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfLiteral;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStamper;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfWriter;
import com.lowagie.text.xml.xmp.XmpReader;
import com.lowagie.text.xml.xmp.XmpWriter;

public abstract class ITextPdfServiceHelper {

  public static final String DEFAULT_APPEARANCE = "/Helv 0 Tf 0 g";

  private ITextPdfServiceHelper() {
    //
  }

  public static boolean isPdf(final ByteSource data) {
    if (data == null) {
      return false;
    }

    PdfReader reader = null;
    try {
      reader = new PdfReader(data.openStream());
      reader.close();
      return true;
    } catch (Exception e) {
      ICryptoLog.getLogger().debug(e.getMessage());
      return false;
    } finally {
      if (reader != null) {
        reader.close();
      }
    }
  }

  public static boolean isSigned(final ByteSource data) throws IOException {
    if (data == null) {
      return false;
    }

    try (PdfReader reader = new PdfReader(data.openStream())) {
      return ITextPdfServiceHelper.isSigned(reader);
    }
  }

  public static boolean isSigned(final PdfReader reader) {
    AcroFields acroFields = reader.getAcroFields();
    List<String> signatureNames = acroFields.getSignedFieldNames();
    for (String name : signatureNames) {
      PdfDictionary pdfDictionary = acroFields.getSignatureDictionary(name);
      PdfObject pdfObject = pdfDictionary.get(PdfName.CONTENTS);
      if (pdfObject != null) {
        byte[] bytes = pdfObject.getBytes();
        if ((bytes != null) && (bytes.length > 0)) {
          return true;
        }
      }
    }
    return false;
  }

  public static PdfDictionary getLastSignature(final PdfReader pdfReader) {
    AcroFields acroFields = pdfReader.getAcroFields();
    if (acroFields != null) {
      List<String> signedFieldNames = acroFields.getSignedFieldNames();
      if ((signedFieldNames != null) && (!signedFieldNames.isEmpty())) {
        PdfDictionary pdfDictionary = null;
        Date lastDate = null;
        for (String signatureName : signedFieldNames) {
          PdfPKCS7 pkcs7 = acroFields.verifySignature(signatureName, BcProvider.PROVIDER_NAME);
          Date currentDate = pkcs7.getSignDate().getTime();
          if ((lastDate == null) || (lastDate.before(currentDate))) {
            lastDate = currentDate;
            pdfDictionary = acroFields.getSignatureDictionary(signatureName);
          }
        }
        return pdfDictionary;
      }
    }
    return null;
  }

  @SuppressWarnings("deprecation")
  public static boolean isLastSignatureMatching(final ByteSource original, final ByteSource signed) throws IOException {
    try (PdfReader pdfReader = new PdfReader(signed.openStream())) {
      PdfDictionary pdfDictionary = ITextPdfServiceHelper.getLastSignature(pdfReader);
      PdfDictionary digestDictionary = pdfDictionary.getAsDict(new PdfName("Digest"));
      if (digestDictionary != null) {
        PdfString sha512 = digestDictionary.getAsString(new PdfName("SHA512"));
        if (sha512 != null) {
          String originalHash = original.hash(Hashing.sha512()).toString().toLowerCase();
          if (sha512.toUnicodeString().equalsIgnoreCase(originalHash)) {
            return true;
          }
          return false;
        }

        PdfString sha256 = digestDictionary.getAsString(new PdfName("SHA256"));
        if (sha256 != null) {
          String originalHash = original.hash(Hashing.sha256()).toString().toLowerCase();
          if (sha256.toUnicodeString().equalsIgnoreCase(originalHash)) {
            return true;
          }
          return false;
        }

        PdfString sha1 = digestDictionary.getAsString(new PdfName("SHA1"));
        if (sha1 != null) {
          String originalHash = original.hash(Hashing.sha1()).toString().toLowerCase();
          if (sha1.toUnicodeString().equalsIgnoreCase(originalHash)) {
            return true;
          }
          return false;
        }
      }
      return false;
    }
  }

  @SuppressWarnings("deprecation")
  public static PdfDictionary getCryptoDictionary(final PadesSignatureParameters parameters, final File inputFile) {
    PdfDictionary dictionary = new PdfDictionary();
    dictionary.put(PdfName.TYPE, PdfName.SIG);

    if (!Strings.isNullOrEmpty(parameters.getFilter())) {
      dictionary.put(PdfName.FILTER, new PdfName(parameters.getFilter()));
    } else {
      dictionary.put(PdfName.FILTER, PdfName.ADOBE_PPKLITE);
    }
    if (!Strings.isNullOrEmpty(parameters.getSubFilter())) {
      dictionary.put(PdfName.SUBFILTER, new PdfName(parameters.getSubFilter()));
    } else {
      dictionary.put(PdfName.SUBFILTER, new PdfName("ETSI.CAdES.detached"));
    }
    dictionary.put(PdfName.NAME, new PdfString(parameters.getName(), PdfObject.TEXT_UNICODE));
    dictionary.put(PdfName.REASON, new PdfString(parameters.getReason(), PdfObject.TEXT_UNICODE));
    dictionary.put(PdfName.DA, new PdfString(ITextPdfServiceHelper.DEFAULT_APPEARANCE, PdfObject.TEXT_UNICODE));
    dictionary.put(PdfName.M, new PdfDate(Calendar.getInstance()));

    if (parameters.getLocation() != null) {
      dictionary.put(PdfName.LOCATION, new PdfString(parameters.getLocation().getLocalityName(), PdfObject.TEXT_UNICODE));
    }

    PdfDictionary propBuild = new PdfDictionary();

    PdfDictionary propBuildApp = new PdfDictionary();
    propBuildApp.put(PdfName.NAME, new PdfName("iCrypto"));
    propBuildApp.put(PdfName.R, new PdfNumber(100));
    PdfArray propBuildAppOs = new PdfArray();
    propBuildAppOs.add(new PdfName(System.getProperty("os.name")));
    propBuildApp.put(new PdfName("OS"), propBuildAppOs);
    // propBuildApp.setDirect(true);
    propBuild.put(new PdfName("APP"), propBuildApp);

    PdfDictionary propBuildFilter = new PdfDictionary();
    propBuildFilter.put(PdfName.NAME, PdfName.ADOBE_PPKLITE);
    propBuildFilter.put(new PdfName("DATE"), new PdfDate(Calendar.getInstance()));
    // propBuildFilter.setDirect(true);
    propBuild.put(PdfName.FILTER, propBuildFilter);
    // propBuild.setDirect(true);

    dictionary.put(new PdfName("Prop_Build"), propBuild);

    try {
      String sha1 = Files.asByteSource(inputFile).hash(Hashing.sha1()).toString().toLowerCase();
      String sha256 = Files.asByteSource(inputFile).hash(Hashing.sha256()).toString().toLowerCase();
      String sha512 = Files.asByteSource(inputFile).hash(Hashing.sha512()).toString().toLowerCase();

      PdfDictionary hash = new PdfDictionary();
      hash.put(new PdfName("SHA1"), new PdfString(sha1));
      hash.put(new PdfName("SHA256"), new PdfString(sha256));
      hash.put(new PdfName("SHA512"), new PdfString(sha512));
      dictionary.put(new PdfName("Digest"), hash);
    } catch (IOException e) {
      ICryptoLog.getLogger().warn(e.getMessage(), e);
    }

    return dictionary;
  }

  // ITextPDFSignatureService
  public static PdfObject toStream(final PdfWriter writer, final Map<String, PdfObject> streams, final byte[] data) throws IOException {
    byte[] hash = Hashing.sha256().hashBytes(data).asBytes();
    String hex = BaseEncoding.base16().encode(hash);
    PdfObject obj = streams.get(hex);

    if (obj == null) {
      PdfStream stream = new PdfStream(data);
      obj = writer.addToBody(stream, false).getIndirectReference();
      streams.put(hex, obj);
    }

    return obj;
  }

  @SuppressWarnings("deprecation")
  public static String getDeterministicId(final Date signingTime) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeLong(signingTime.getTime());
    dos.flush();
    return "id-" + Hashing.md5().hashBytes(baos.toByteArray()).toString();
  }

  public static PdfObject generateFileId() throws IOException {
    ByteBuffer buf = new ByteBuffer(90);
    String deterministicId = ITextPdfServiceHelper.getDeterministicId(new Date());
    byte[] id = deterministicId.getBytes();
    buf.append('[').append('<');
    for (int k = 0; k < 16; ++k) {
      buf.appendHex(id[k]);
    }
    buf.append('>').append('<');
    for (int k = 0; k < 16; ++k) {
      buf.appendHex(id[k]);
    }
    buf.append('>').append(']');
    byte[] bytes = buf.toByteArray();
    buf.close();
    return new PdfLiteral(bytes);
  }

  public static void handleXmpModifyDate(final PdfStamper pdfStamper, final Calendar calendar) throws IOException, SAXException {
    PdfReader reader = pdfStamper.getReader();
    PdfDate pdfDate = new PdfDate(calendar);
    byte[] xmp = reader.getMetadata();
    if (xmp != null) {
      XmpReaderFixed xmpReader = new XmpReaderFixed(xmp);
      if (!xmpReader.replace("http://ns.adobe.com/xap/1.0/", "ModifyDate", pdfDate.getW3CDate())) {
        // xmpr.add("rdf:Description", "http://ns.adobe.com/xap/1.0/", "xap:ModifyDate", pdfDate.getW3CDate());
        xmpReader.add("rdf:Description", "http://ns.adobe.com/xap/1.0/", "ModifyDate", pdfDate.getW3CDate());
      }
      pdfStamper.setXmpMetadata(xmpReader.serializeDoc());
    } else {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      XmpWriter xmpWriter = new XmpWriter(outputStream);
      xmpWriter.addRdfDescription("xmlns:xmp=\"http://ns.adobe.com/xap/1.0/\"", "<xmp:ModifyDate>" + pdfDate.getW3CDate() + "</xmp:ModifyDate>");
      xmpWriter.close();
      pdfStamper.setXmpMetadata(outputStream.toByteArray());
    }
  }

  private static class XmpReaderFixed extends XmpReader {

    private static final Field FIELD;

    static {
      try {
        Field field = XmpReader.class.getDeclaredField("domDocument");
        field.setAccessible(true);
        FIELD = field;
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }

    public XmpReaderFixed(final byte[] xmp) throws SAXException, IOException {
      super(xmp);
    }

    @Override
    public boolean add(String parent, String namespaceURI, String localName, String value) {
      try {
        Document domDocument = (Document) XmpReaderFixed.FIELD.get(this);
        NodeList nodes = domDocument.getElementsByTagName(parent);
        if (nodes.getLength() == 0) {
          return false;
        }
        for (int i = 0; i < nodes.getLength(); i++) {
          Node pNode = nodes.item(i);
          NamedNodeMap attrs = pNode.getAttributes();
          for (int j = 0; j < attrs.getLength(); j++) {
            Node node = attrs.item(j);
            String newLocalName = localName;
            if (namespaceURI.equals(node.getNodeValue())) {
              if (localName.indexOf(":") == -1) {
                String nodeName = node.getNodeName();
                if (nodeName.startsWith("xmlns")) {
                  String prefix = nodeName.substring(6);
                  newLocalName = prefix + ":" + localName;
                }
              }
              node = domDocument.createElement(newLocalName);
              node.appendChild(domDocument.createTextNode(value));
              pNode.appendChild(node);
              return true;
            }
          }
        }
        return false;
      } catch (Exception e) {
        ICryptoLog.getLogger().error(e.getMessage(), e);
        return false;
      }
    }

  }

}
