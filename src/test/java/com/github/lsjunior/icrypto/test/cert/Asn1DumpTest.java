package com.github.lsjunior.icrypto.test.cert;

import java.io.File;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.lsjunior.icrypto.core.certificate.util.Certificates;
import com.google.common.io.Files;

public class Asn1DumpTest {

  public Asn1DumpTest() {
    super();
  }

  @Test
  @Disabled
  void testCert() throws Exception {
    File file1 = new File("D:\\Trabalho\\PKI\\1.cer");
    this.ans1dump(file1);
    // File file2 = new File("D:\\Trabalho\\PKI\\ressoa-hmg.apps.mma.gov.br.crt");
    // File file2 = new File("D:\\Workspaces\\projects-lidersis\\pki\\source\\pki-https-test\\src\\main\\resources\\dev.woodstock.net.br-v5.crt");
    // this.ans1dump(file2);

    // https
    // https://crt.sh/lintcert ver esse site
    // remover o 2.5.29.19
    // adicionar o 1.3.6.1.4.1.11129.2.4.2
    // https://oidref.com/1.3.6.1.4.1.11129.2.4.2
    // https://certificate.transparency.dev/
    /*
     * cablint ERROR BR certificates must contain at least one policy cablint WARNING BR certificates should include an HTTP URL of the issuing CA's certificate cablint INFO TLS Server certificate identified x509lint WARNING No HTTP URL for
     * issuing certificate x509lint INFO Checking as leaf certificate x509lint INFO Subject has a deprecated CommonName x509lint INFO Unknown validation policy zlint ERROR The certificate MUST only be used for a purpose consistent with both
     * key usage extension and extended key usage extension. zlint WARNING Sub certificates SHOULD include Subject Key Identifier in end entity certs zlint WARNING Subscriber Certificate: commonName is NOT RECOMMENDED. zlint WARNING
     * Subscriber certificates authorityInformationAccess extension should contain the HTTP URL of the issuing CA’s certificate zlint WARNING Subscriber certificates authorityInformationAccess extension should contain the HTTP URL of the
     * issuing CA’s certificate, for public certificates this should not be an internal name zlint NOTICE Check if certificate has enough embedded SCTs to meet Apple CT Policy
     */
  }

  @Test
  @Disabled
  void testCa() throws Exception {
    File file1 = new File("D:\\Trabalho\\PKI\\2.cer");
    this.ans1dump(file1);
    File file2 = new File("D:\\Trabalho\\PKI\\lidersis-ca-v2.crt");
    this.ans1dump(file2);

    // https
    // remover o 2.5.29.19
    // adicionar o 1.3.6.1.4.1.11129.2.4.2
    // https://oidref.com/1.3.6.1.4.1.11129.2.4.2
    // https://certificate.transparency.dev/
  }

  @Test
  @Disabled
  void testRoot() throws Exception {
    File file1 = new File("D:\\Trabalho\\PKI\\3.cer");
    this.ans1dump(file1);
    File file2 = new File("D:\\Trabalho\\PKI\\lidersis-root-v2.crt");
    this.ans1dump(file2);

    // https
    // remover o 2.5.29.19
    // adicionar o 1.3.6.1.4.1.11129.2.4.2
    // https://oidref.com/1.3.6.1.4.1.11129.2.4.2
    // https://certificate.transparency.dev/
  }

  @Test
  // @Disabled
  void testIcp() throws Exception {
    File file1 = new File("D:\\Trabalho\\PKI\\86216503120.cer");
    this.ans1dump(file1);

    // https
    // remover o 2.5.29.19
    // adicionar o 1.3.6.1.4.1.11129.2.4.2
    // https://oidref.com/1.3.6.1.4.1.11129.2.4.2
    // https://certificate.transparency.dev/
  }

  private void ans1dump(final File file) throws Exception {
    Certificate certificate = Certificates.toCertificate(Files.toByteArray(file));
    X509Certificate x509Certificate = (X509Certificate) certificate;
    System.out.println(x509Certificate.getSerialNumber());
    System.out.println(x509Certificate.getCriticalExtensionOIDs());
    System.out.println(x509Certificate.getNonCriticalExtensionOIDs());
    System.out.println("=======================================================");

    X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certificate.getEncoded());
    Extension extension = x509CertificateHolder.getExtension(ASN1ObjectIdentifier.tryFromID("2.5.29.32"));
    System.out.println(extension);

    CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(extension.getParsedValue());
    System.out.println(certificatePolicies);
    for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
      System.out.println("  " + policyInformation.getPolicyIdentifier() + " => " + policyInformation.getPolicyQualifiers());
      if (policyInformation.getPolicyQualifiers() != null) {
        for (int i = 0; i < policyInformation.getPolicyQualifiers().size(); i++) {
          ASN1Encodable obj = policyInformation.getPolicyQualifiers().getObjectAt(i);
          PolicyQualifierInfo policyQualifierInfo = PolicyQualifierInfo.getInstance(obj);
          System.out.println("    " + policyQualifierInfo.getPolicyQualifierId() + " => " + ASN1IA5String.getInstance(policyQualifierInfo.getQualifier()));
        }
      }
    }

    // String str = Asn1Objects.dump(certificate.getEncoded(), true);
    // System.out.println(str);
    // File out = new File(file.getParentFile(), file.getName() + ".txt");
    // Files.asCharSink(out, StandardCharsets.UTF_8).write(str);
  }

}
