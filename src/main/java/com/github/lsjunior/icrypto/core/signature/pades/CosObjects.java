package com.github.lsjunior.icrypto.core.signature.pades;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;

import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.util.Crls;

public abstract class CosObjects {

  private CosObjects() {
    //
  }

  public static List<Certificate> getCertificates(final COSDictionary dictionary, final String name) throws IOException {
    COSArray array = (COSArray) dictionary.getDictionaryObject(name);
    return CosObjects.getCertificates(array);
  }

  public static List<Certificate> getCertificates(final COSArray array) throws IOException {
    if (array != null) {
      List<Certificate> list = new ArrayList<>();
      for (int i = 0; i < array.size(); i++) {
        COSBase base = array.get(i);
        COSObject obj = (COSObject) base;
        COSStream stream = (COSStream) obj.getObject();
        Certificate certificate = Certificates.toCertificate(stream.createInputStream());
        list.add(certificate);
      }
      return list;
    }
    return null;
  }

  public static List<CRL> getCrls(final COSDictionary dictionary, final String name) throws IOException, GeneralSecurityException {
    COSArray array = (COSArray) dictionary.getDictionaryObject(name);
    return CosObjects.getCrls(array);
  }

  public static List<CRL> getCrls(final COSArray array) throws IOException, GeneralSecurityException {
    if (array != null) {
      List<CRL> list = new ArrayList<>();
      for (int i = 0; i < array.size(); i++) {
        COSBase base = array.get(i);
        COSObject obj = (COSObject) base;
        COSStream stream = (COSStream) obj.getObject();
        CRL crl = Crls.toCrl(stream.createInputStream());
        list.add(crl);
      }
      return list;
    }
    return null;
  }

  public static List<BasicOCSPResp> getOcsps(final COSDictionary dictionary, final String name) throws IOException, OCSPException {
    COSArray array = (COSArray) dictionary.getDictionaryObject(name);
    return CosObjects.getOcsps(array);
  }

  public static List<BasicOCSPResp> getOcsps(final COSArray array) throws IOException, OCSPException {
    if (array != null) {
      List<BasicOCSPResp> list = new ArrayList<>();
      for (int i = 0; i < array.size(); i++) {
        COSBase base = array.get(i);
        COSObject obj = (COSObject) base;
        COSStream stream = (COSStream) obj.getObject();
        OCSPResp ocspResp = new OCSPResp(stream.createInputStream());
        BasicOCSPResp basicOcspResp = (BasicOCSPResp) ocspResp.getResponseObject();
        list.add(basicOcspResp);
      }
      return list;
    }
    return null;
  }

}
