package com.github.lsjunior.icrypto.api.model;

public enum AlternativeNameType {
  OTHER_NAME(0), /**/
  RFC_822_NAME(1), /**/
  DNS_NAME(2), /**/
  X400ADDRESS(3), /**/
  DIRECTORY_NAME(4), /**/
  EDI_PART_NAME(5), /**/
  UNIFORM_RESOURCE_IDENTIFIER(6), /**/
  IP_ADDRESS(7), /**/
  REGISTERED_ID(8); /**/

  private int type;

  private AlternativeNameType(final int type) {
    this.type = type;
  }

  public int getType() {
    return this.type;
  }
}
