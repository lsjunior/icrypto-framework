package com.github.lsjunior.icrypto.api.type;

public enum KeySizeType {

  /* @formatter:off */
  KEYSIZE_1K(1024, "1024 bits"),
  KEYSIZE_2K(2048, "2048 bits"),
  KEYSIZE_4K(4096, "4096 bits"),
  KEYSIZE_8K(8192, "8192 bits"),
  KEYSIZE_16K(16384, "16384 bits");
  /* @formatter:on */

  private final int size;

  private final String label;

  private KeySizeType(final int size, final String label) {
    this.size = size;
    this.label = label;
  }

  public int getSize() {
    return this.size;
  }

  @Override
  public String toString() {
    return this.label;
  }
}
