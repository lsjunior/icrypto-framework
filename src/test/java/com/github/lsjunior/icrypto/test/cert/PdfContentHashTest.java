package com.github.lsjunior.icrypto.test.cert;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import com.lowagie.text.pdf.PdfReader;

public class PdfContentHashTest {

  @Test
  void testIDoct() throws Exception {
    File original = new File("D:\\Trabalho\\Lidersis\\pki\\53001082252633131000100000000000000424105166988718.pdf");
    File signed = new File("D:\\Trabalho\\Lidersis\\pki\\53001082252633131000100000000000000424105166988718-signed.pdf");
    this.printContentHash(original, signed);
  }

  @Test
  void testGovbr() throws Exception {
    File original = new File("D:\\Trabalho\\Lidersis\\pki\\53001082252633131000100000000000000424105166988718.pdf");
    File signed = new File("D:\\Trabalho\\Lidersis\\pki\\53001082252633131000100000000000000424105166988718_assinado.pdf");
    this.printContentHash(original, signed);
  }

  @Test
  void testIDoctGovbr() throws Exception {
    File original = new File("D:\\Trabalho\\Lidersis\\pki\\53001082252633131000100000000000000424105166988718.pdf");
    File signed = new File("D:\\Trabalho\\Lidersis\\pki\\53001082252633131000100000000000000424105166988718-signed_assinado.pdf");
    this.printContentHash(original, signed);
  }

  private void printContentHash(final File original, final File signed) throws IOException {
    PdfReader readerOriginal = new PdfReader(new FileInputStream(original));
    PdfReader readerSigned = new PdfReader(new FileInputStream(signed));
    int pageCountOriginal = readerOriginal.getNumberOfPages();
    int pageCountSigned = readerSigned.getNumberOfPages();
    if (pageCountOriginal != pageCountSigned) {
      throw new IllegalStateException("Page count not match");
    }
    for (int i = 1; i <= pageCountOriginal; i++) {
      byte[] pageContentOriginal = readerOriginal.getPageContent(i);
      byte[] pageContentSigned = readerSigned.getPageContent(i);
      if (!Arrays.equals(pageContentOriginal, pageContentSigned)) {
        throw new IllegalStateException("Page content not match for page " + i);
      }
    }
  }

}
