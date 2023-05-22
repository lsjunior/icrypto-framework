package com.github.lsjunior.icrypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class ICryptoLog {

  private static final Logger LOGGER = LoggerFactory.getLogger(ICryptoConstants.BASE_PACKAGE);

  private ICryptoLog() {
    //
  }

  public static Logger getLogger() {
    return ICryptoLog.LOGGER;
  }
}
