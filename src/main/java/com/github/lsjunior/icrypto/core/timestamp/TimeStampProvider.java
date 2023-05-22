package com.github.lsjunior.icrypto.core.timestamp;

import com.github.lsjunior.icrypto.api.type.DigestType;

public interface TimeStampProvider {

  byte[] getTimeStamp(byte[] data, DigestType digestType);

}
