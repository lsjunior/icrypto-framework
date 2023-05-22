package com.github.lsjunior.icrypto.core.timestamp.impl;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.function.Function;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.SignatureType;
import com.github.lsjunior.icrypto.core.Identity;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampService;

public class LocalTimeStampService implements TimeStampService, Serializable {

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  private Identity identity;

  private String policyId;

  private Function<byte[], BigInteger> serialNumberFunction;

  private transient TimeStampTokenGenerator timeStampTokenGenerator;

  public LocalTimeStampService(final Identity identity, final String policyId) {
    this(identity, policyId, null);
  }

  public LocalTimeStampService(final Identity identity, final String policyId, final Function<byte[], BigInteger> serialNumberFunction) {
    super();
    this.identity = identity;
    this.policyId = policyId;
    this.serialNumberFunction = serialNumberFunction;

    if (this.serialNumberFunction == null) {
      this.serialNumberFunction = (request) -> {
        return new BigInteger(Long.toString(System.currentTimeMillis()));
      };
    }
  }

  private synchronized void init() {
    try {
      if (this.timeStampTokenGenerator != null) {
        return;
      }
      PrivateKey privateKey = this.identity.getPrivateKey();
      List<Certificate> chain = this.identity.getChain();

      Certificate certificate = chain.get(0);

      JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SignatureType.SHA1_RSA.getAlgorithm());
      contentSignerBuilder.setProvider(AbstractTimeStampProvider.PROVIDER_NAME);

      ContentSigner contentSigner = contentSignerBuilder.build(privateKey);

      JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder();
      digestCalculatorProviderBuilder.setProvider(AbstractTimeStampProvider.PROVIDER_NAME);
      DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();

      JcaSignerInfoGeneratorBuilder signerInfoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(digestCalculatorProvider);

      SignerInfoGenerator signerInfoGenerator = signerInfoGeneratorBuilder.build(contentSigner, (X509Certificate) certificate);

      DigestCalculator digestCalculator = digestCalculatorProvider.get(signerInfoGenerator.getDigestAlgorithm());

      this.timeStampTokenGenerator = new TimeStampTokenGenerator(signerInfoGenerator, digestCalculator, new ASN1ObjectIdentifier(this.policyId));

      JcaCertStore certStore = new JcaCertStore(chain);
      this.timeStampTokenGenerator.addCertificates(certStore);
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  @Override
  public byte[] generate(final byte[] request) {
    try {
      if (this.timeStampTokenGenerator == null) {
        this.init();
      }
      TimeStampRequest timeStampRequest = new TimeStampRequest(request);

      TimeStampResponseGenerator timeStampResponseGenerator = new TimeStampResponseGenerator(this.timeStampTokenGenerator, TSPAlgorithms.ALLOWED);

      TimeStampResponse timeStampResponse = timeStampResponseGenerator.generate(timeStampRequest, this.serialNumberFunction.apply(request), new Date());

      timeStampResponse.validate(timeStampRequest);

      return timeStampResponse.getEncoded();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

}
