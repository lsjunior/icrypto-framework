package com.github.lsjunior.icrypto.core.signature.pades;

import com.github.lsjunior.icrypto.core.signature.cms.CadesErrors;

public abstract class PadesErrors extends CadesErrors {

  // Core
  public static final int UNCAUGHT_ERROR = 1000;

  public static final int FILTER_INVALID = 1001;

  public static final int SUBFILTER_INVALID = 1002;

  public static final int FORMAT_INSECURE = 1003;

  public static final int ALGORITHM_INSECURE = 1004;

  private PadesErrors() {
    //
  }

}
