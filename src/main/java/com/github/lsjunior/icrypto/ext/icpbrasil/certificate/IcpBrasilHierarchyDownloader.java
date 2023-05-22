package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.zip.ZipInputStream;

import com.github.lsjunior.icrypto.ICryptoLog;
import com.github.lsjunior.icrypto.core.certificate.util.Certificates;

public abstract class IcpBrasilHierarchyDownloader {

  public static final String URL = "http://acraiz.icpbrasil.gov.br/credenciadas/CertificadosAC-ICP-Brasil/ACcompactado.zip";

  private IcpBrasilHierarchyDownloader() {
    super();
  }

  public static Map<String, Certificate> getCertificates() throws IOException {
    return IcpBrasilHierarchyDownloader.getCertificates(new URL(IcpBrasilHierarchyDownloader.URL));
  }

  public static Map<String, Certificate> getCertificates(final URL url) throws IOException {
    ICryptoLog.getLogger().info("Baixando cadeia ICP-Brasil da URL " + url);
    URLConnection connection = url.openConnection();
    try (InputStream inputStream = connection.getInputStream()) {
      Map<String, Certificate> certificates = IcpBrasilHierarchyDownloader.getCertificates(inputStream);
      return certificates;
    }
  }

  public static Map<String, Certificate> getCertificates(final InputStream inputStream) throws IOException {
    try (ZipInputStream zipInputStream = new ZipInputStream(inputStream)) {
      Map<String, Certificate> certificates = Certificates.toCertificates(zipInputStream);
      return certificates;
    }
  }
}
