package com.github.lsjunior.icrypto.core.certificate.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

import com.github.lsjunior.icrypto.core.digest.util.Digesters;

public abstract class OpenSslCertificates {

  private OpenSslCertificates() {
    //
  }

  private static String toOpensslString(final byte[] digest) {
    Integer int0 = Integer.valueOf(digest[0] & 0xFF);
    Integer int1 = Integer.valueOf(digest[1] & 0xFF);
    Integer int2 = Integer.valueOf(digest[2] & 0xFF);
    Integer int3 = Integer.valueOf(digest[3] & 0xFF);

    String ret = String.format("%02x%02x%02x%02x", int3, int2, int1, int0);
    return ret;
  }

  public static String getOpenSslHash(final X500Principal name) throws IOException {
    return OpenSslCertificates.getOpenSslHashNew(name);
  }

  public static String getOpenOpenSslHashOld(final X500Principal name) {
    byte[] encoded = name.getEncoded();
    byte[] digest = Digesters.MD5.digest(encoded);
    return OpenSslCertificates.toOpensslString(digest);
  }

  public static String getOpenSslHashNew(final X500Principal name) throws IOException {
    RDN[] c19nrdns = OpenSslCertificates.getNormalizedRdns(name);
    byte[] encoded = OpenSslCertificates.encodeWithoutSeqHeader(c19nrdns);
    byte[] digest = Digesters.SHA1.digest(encoded);

    return OpenSslCertificates.toOpensslString(digest);
  }

  public static RDN[] getNormalizedRdns(final X500Principal name) throws IOException {
    X500Name dn = Certificates.toX500Name(name);
    RDN[] rdns = dn.getRDNs();
    RDN[] newRdns = new RDN[rdns.length];
    for (int i = 0; i < rdns.length; i++) {
      RDN rdn = rdns[i];
      AttributeTypeAndValue[] atvs = rdn.getTypesAndValues();
      OpenSslCertificates.sortOpensslAttributes(atvs);
      AttributeTypeAndValue[] c19natvs = new AttributeTypeAndValue[atvs.length];
      for (int j = 0; j < atvs.length; j++) {
        c19natvs[j] = OpenSslCertificates.normalizeAttribute(atvs[j]);
      }
      newRdns[i] = new RDN(c19natvs);
    }
    return newRdns;
  }

  private static void sortOpensslAttributes(final AttributeTypeAndValue[] attrs) throws IOException {
    for (int i = 0; i < attrs.length; i++) {
      for (int j = i + 1; j < attrs.length; j++) {
        if (OpenSslCertificates.memcmp(attrs[i].getEncoded(), attrs[j].getEncoded()) < 0) {
          AttributeTypeAndValue tmp = attrs[i];
          attrs[i] = attrs[j];
          attrs[j] = tmp;
        }
      }
    }
  }

  private static int memcmp(final byte[] a, final byte[] b) {
    int min = a.length > b.length ? b.length : a.length;
    for (int i = 0; i < min; i++) {
      if (a[i] < b[i]) {
        return -1;
      } else if (a[i] > b[i]) {
        return 1;
      }
    }
    return a.length - b.length;
  }

  private static AttributeTypeAndValue normalizeAttribute(final AttributeTypeAndValue attr) {
    ASN1Encodable encodable = attr.getValue();
    if (!(encodable instanceof ASN1String)) {
      return attr;
    }
    ASN1String asn1String = (ASN1String) encodable;
    String value = asn1String.getString();
    value = value.trim();
    value = value.replaceAll("[ \t\n\f][ \t\n\f]+", " ");
    value = value.toLowerCase();
    DERUTF8String derUtf8String = new DERUTF8String(value);
    return new AttributeTypeAndValue(attr.getType(), derUtf8String);
  }

  private static byte[] encodeWithoutSeqHeader(final RDN[] rdns) throws IOException {
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    ASN1OutputStream asn1OutptuStream = ASN1OutputStream.create(outputStream);

    for (RDN rdn : rdns) {
      asn1OutptuStream.writeObject(rdn);
    }
    asn1OutptuStream.close();
    return outputStream.toByteArray();
  }

}
