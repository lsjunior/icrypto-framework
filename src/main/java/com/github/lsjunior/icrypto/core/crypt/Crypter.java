package com.github.lsjunior.icrypto.core.crypt;

public interface Crypter {

  byte[] encrypt(byte[] data);

  byte[] encrypt(byte[] data, String seed);

  byte[] decrypt(byte[] data);

  byte[] decrypt(byte[] data, String seed);

}
