package com.github.lsjunior.icrypto.test.cert;

import java.io.File;
import java.security.cert.Certificate;
import java.util.Collection;

import org.junit.jupiter.api.Test;

import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.github.lsjunior.icrypto.core.crl.util.Crls;
import com.github.lsjunior.icrypto.core.ocsp.util.Ocsps;
import com.google.common.io.Files;

public class CertificadoSerproTest {

  @Test
  void testSerpro() throws Exception {
    System.out.println("SERPRO #################################");
    File file = new File("D:\\Trabalho\\Lidersis\\pki\\lourival-serpro.cer");
    this.printCrlUrl(file);
    this.printOcspUrl(file);
  }

  @Test
  void testGovbr() throws Exception {
    System.out.println("GOVBR #################################");
    File file = new File("D:\\Trabalho\\Lidersis\\pki\\lourival-govbr.cer");
    this.printCrlUrl(file);
    this.printOcspUrl(file);
  }

  private void printCrlUrl(final File file) throws Exception {
    Certificate certificate = Certificates.toCertificate(Files.toByteArray(file));
    Collection<String> urls = Crls.getCrlUrlsAsString(certificate);
    for (String url : urls) {
      System.out.println(url);
    }
  }

  private void printOcspUrl(final File file) throws Exception {
    Certificate certificate = Certificates.toCertificate(Files.toByteArray(file));
    Collection<String> urls = Ocsps.getOcspUrlsAsString(certificate);
    for (String url : urls) {
      System.out.println(url);
    }
  }

}
