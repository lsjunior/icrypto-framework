package com.github.lsjunior.icrypto.core.timestamp.impl;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import com.github.lsjunior.icrypto.ICryptoConstants;
import com.github.lsjunior.icrypto.ICryptoException;
import com.github.lsjunior.icrypto.api.type.DigestType;
import com.github.lsjunior.icrypto.core.timestamp.TimeStampProvider;
import com.github.lsjunior.icrypto.core.util.BcProvider;

abstract class AbstractTimeStampProvider implements TimeStampProvider, Serializable {

  public static final String PROVIDER_NAME = BcProvider.PROVIDER_NAME;

  private static final long serialVersionUID = ICryptoConstants.VERSION;

  public AbstractTimeStampProvider() {
    super();
  }

  @Override
  public byte[] getTimeStamp(final byte[] data, final DigestType digestType) {
    try {
      org.bouncycastle.tsp.TimeStampRequest tsr = this.toTimeStampRequest(data, digestType);

      byte[] response = this.execute(tsr.getEncoded());

      TimeStampResponse timeStampResponse = new TimeStampResponse(response);

      TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();

      if (timeStampToken == null) {
        throw new IllegalStateException("TimeStampToken not found in response");
      }

      return timeStampToken.getEncoded();
    } catch (Exception e) {
      throw new ICryptoException(e);
    }
  }

  protected TimeStampRequest toTimeStampRequest(final byte[] data, final DigestType digestType) {
    TimeStampRequestGenerator generator = new TimeStampRequestGenerator();
    generator.setCertReq(true);

    BigInteger nonce = BigInteger.valueOf(System.currentTimeMillis());
    org.bouncycastle.tsp.TimeStampRequest tsr = generator.generate(digestType.getIdentifier(), data, nonce);

    return tsr;
  }

  protected abstract byte[] execute(byte[] request);

}
