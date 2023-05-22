package com.github.lsjunior.icrypto.core.util;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.github.lsjunior.icrypto.ICryptoLog;

public abstract class BcProvider {

  public static final String PROVIDER_NAME;

  static {
    PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    Provider provider = Security.getProvider(BcProvider.PROVIDER_NAME);
    if (provider == null) {
      ICryptoLog.getLogger().debug("Adding BouncyCastle Security Provider");
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private BcProvider() {
    //
  }

  public static boolean isActive() {
    Provider provider = Security.getProvider(BcProvider.PROVIDER_NAME);
    if (provider != null) {
      return true;
    }
    return false;
  }

}
