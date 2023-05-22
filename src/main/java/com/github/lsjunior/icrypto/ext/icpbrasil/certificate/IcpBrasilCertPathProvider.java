package com.github.lsjunior.icrypto.ext.icpbrasil.certificate;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.core.certificate.impl.DefaultCertPathProvider;

public class IcpBrasilCertPathProvider extends DefaultCertPathProvider {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public IcpBrasilCertPathProvider() throws IOException {
    super(IcpBrasilHierarchyDownloader.getCertificates().values());
  }

  public IcpBrasilCertPathProvider(final URL url) throws IOException {
    super(IcpBrasilHierarchyDownloader.getCertificates(url).values());
  }

  public IcpBrasilCertPathProvider(final InputStream inputStream) throws IOException {
    super(IcpBrasilHierarchyDownloader.getCertificates(inputStream).values());
  }

}
