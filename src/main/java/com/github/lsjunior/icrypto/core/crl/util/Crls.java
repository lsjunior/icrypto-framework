package com.github.lsjunior.icrypto.core.crl.util;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaCRLStore;
import org.bouncycastle.util.Store;

import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.api.type.CertificateType;
import com.github.lsjunior.icrypto.core.net.JdkWebClient;
import com.github.lsjunior.icrypto.core.net.WebClient;
import com.github.lsjunior.icrypto.core.util.Asn1Objects;
import com.google.common.base.Strings;
import com.google.common.io.Files;

public abstract class Crls {

  private static final int SEMAPHORE_TIMEOUT = 120;

  private static final int NEXT_UPDATE = 60;

  private static final Map<String, CrlData> CRL_MAP = new HashMap<>();

  private static final String CRL_PREFIX = "CRL-";

  private static final String CRL_SUFFIX = ".crl";

  private static final WebClient WEB_CLIENT = new JdkWebClient();

  private Crls() {
    //
  }

  // CRL
  public static CRL toCrl(final byte[] bytes) throws GeneralSecurityException {
    if (bytes == null) {
      return null;
    }
    return Crls.toCrl(new ByteArrayInputStream(bytes));
  }

  public static CRL toCrl(final InputStream inputStream) throws GeneralSecurityException {
    if (inputStream == null) {
      return null;
    }
    CertificateFactory factory = CertificateFactory.getInstance(CertificateType.X509.getType());
    CRL crl = factory.generateCRL(inputStream);
    return crl;
  }

  public static Collection<CRL> getCrls(final Certificate certificate) throws IOException {
    Collection<URL> urls = Crls.getCrlUrls(certificate);
    Collection<CRL> crls = new ArrayList<>();
    if (urls != null) {
      for (URL url : urls) {
        try {
          CRL crl = Crls.getCrl(url);
          crls.add(crl);
        } catch (Exception e) {
          ICryptoLog.getLogger().debug(e.getMessage(), e);
        }
      }
    } else {
      ICryptoLog.getLogger().info("CRL not found for certificate " + certificate);
    }
    return crls;
  }

  public static CRL getCrl(final Certificate certificate) throws IOException {
    Collection<URL> urls = Crls.getCrlUrls(certificate);
    if (urls != null) {
      for (URL url : urls) {
        try {
          CRL crl = Crls.getCrl(url);
          return crl;
        } catch (Exception e) {
          ICryptoLog.getLogger().debug(e.getMessage(), e);
        }
      }
    } else {
      ICryptoLog.getLogger().info("CRL not found for certificate " + certificate);
    }
    return null;
  }

  public static CRL getCrl(final URL url) throws GeneralSecurityException, IOException {
    String key = url.toString();
    CrlData crlData = Crls.CRL_MAP.get(key);
    if ((crlData == null) || (!crlData.isValid())) {
      if (crlData == null) {
        synchronized (Crls.class) {
          crlData = Crls.CRL_MAP.get(key);
          if (crlData == null) {
            crlData = new CrlData(url, new Semaphore(1));
            Crls.CRL_MAP.put(key, crlData);
          }
        }

      }

      crlData = Crls.CRL_MAP.get(key);

      try {
        crlData.getSemaphore().tryAcquire(Crls.SEMAPHORE_TIMEOUT, TimeUnit.SECONDS);

        if (!crlData.isValid()) {
          ICryptoLog.getLogger().info("Download CRL " + url);
          byte[] bytes = Crls.WEB_CLIENT.get(url.toExternalForm());

          File file = File.createTempFile(Crls.CRL_PREFIX, Crls.CRL_SUFFIX);
          file.deleteOnExit();
          Files.write(bytes, file);

          CertificateFactory factory = CertificateFactory.getInstance(CertificateType.X509.getType());
          CRL crl = factory.generateCRL(new ByteArrayInputStream(bytes));
          X509CRL x509crl = (X509CRL) crl;
          crlData.setFile(file);
          crlData.setDate(x509crl.getThisUpdate());
          if (x509crl.getNextUpdate() != null) {
            crlData.setNextUpdate(x509crl.getNextUpdate());
          } else {
            LocalDateTime localDatetime = LocalDateTime.now().plusMinutes(Crls.NEXT_UPDATE);
            Date nextUpdate = Date.from(localDatetime.atZone(ZoneId.systemDefault()).toInstant());
            crlData.setNextUpdate(nextUpdate);
          }
        }
      } catch (Exception e) {
        throw new ICryptoException(e);
      } finally {
        crlData.getSemaphore().release();
      }

    }

    try (InputStream inputStream = new FileInputStream(crlData.getFile())) {
      CertificateFactory factory = CertificateFactory.getInstance(CertificateType.X509.getType());
      CRL crl = factory.generateCRL(inputStream);
      return crl;
    }
  }

  public static Collection<String> getCrlUrlsAsString(final Certificate certificate) throws IOException {
    X509Certificate x509Certificate = (X509Certificate) certificate;
    byte[] crldistribuitionPointsBytes = x509Certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

    if (crldistribuitionPointsBytes == null) {
      return Collections.emptySet();
    }

    ASN1Primitive crldistribuitionPointsObject = Asn1Objects.toAsn1Primitive(crldistribuitionPointsBytes);
    DEROctetString crldistribuitionPointsString = (DEROctetString) crldistribuitionPointsObject;

    crldistribuitionPointsObject = Asn1Objects.toAsn1Primitive(crldistribuitionPointsString.getOctets());
    CRLDistPoint distPoint = CRLDistPoint.getInstance(crldistribuitionPointsObject);

    Set<String> urls = new HashSet<>();

    for (DistributionPoint distribuitionPoint : distPoint.getDistributionPoints()) {
      DistributionPointName distribuitionPointName = distribuitionPoint.getDistributionPoint();
      if ((distribuitionPointName != null) && (distribuitionPointName.getType() == DistributionPointName.FULL_NAME)) {
        GeneralName[] genNames = GeneralNames.getInstance(distribuitionPointName.getName()).getNames();
        for (int i = 0; i < genNames.length; i++) {
          if (genNames[i].getTagNo() == GeneralName.uniformResourceIdentifier) {
            String urlStr = ASN1IA5String.getInstance(genNames[i].getName()).getString();
            if (!Strings.isNullOrEmpty(urlStr)) {
              urls.add(urlStr);
            }
          }
        }
      }
    }
    return urls;
  }

  public static Collection<URL> getCrlUrls(final Certificate certificate) throws IOException {
    Set<URL> urls = new HashSet<>();
    Collection<String> urlStrs = Crls.getCrlUrlsAsString(certificate);
    for (String urlStr : urlStrs) {
      try {
        URL url = new URL(urlStr);
        urls.add(url);
      } catch (MalformedURLException e) {
        ICryptoLog.getLogger().debug(e.getMessage(), e);
        ICryptoLog.getLogger().info("Invalid URL: " + urlStr);
      }
    }
    return urls;
  }

  // BC
  @SuppressWarnings("rawtypes")
  public static Store toStore(final Collection<CRL> crls) throws CRLException {
    JcaCRLStore crlStore = new JcaCRLStore(crls);
    return crlStore;
  }

  public static List<CRL> toCrls(final Collection<X509CRLHolder> crls) throws GeneralSecurityException, IOException {
    List<CRL> collection = new ArrayList<>();
    if (crls != null) {
      for (X509CRLHolder crl : crls) {
        collection.add(Crls.toCrl(crl.getEncoded()));
      }
    }
    return collection;
  }

}
