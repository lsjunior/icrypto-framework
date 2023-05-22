package com.github.lsjunior.icrypto.core.signature.cms;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSSignatureEncryptionAlgorithmFinder;

public final class RFC5754CMSSignatureEncryptionAlgorithmFinder implements CMSSignatureEncryptionAlgorithmFinder {

  private static RFC5754CMSSignatureEncryptionAlgorithmFinder instance = new RFC5754CMSSignatureEncryptionAlgorithmFinder();

  // RFC3370 section 3.2
  // RFC5754 section 3.2
  private RFC5754CMSSignatureEncryptionAlgorithmFinder() {
    super();
  }

  @Override
  public AlgorithmIdentifier findEncryptionAlgorithm(final AlgorithmIdentifier signatureAlgorithm) {
    return signatureAlgorithm;
  }

  public static RFC5754CMSSignatureEncryptionAlgorithmFinder getInstance() {
    return RFC5754CMSSignatureEncryptionAlgorithmFinder.instance;
  }

}
