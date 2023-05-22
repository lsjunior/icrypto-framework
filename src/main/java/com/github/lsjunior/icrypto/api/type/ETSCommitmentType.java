package com.github.lsjunior.icrypto.api.type;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

public enum ETSCommitmentType {

  // @formatter:off
  PROOF_OF_ORIGIN(PKCSObjectIdentifiers.id_cti_ets_proofOfOrigin.getId(), "Proof of origin"),
  PROOF_OF_RECEIPT(PKCSObjectIdentifiers.id_cti_ets_proofOfReceipt.getId(), "Proof of receipt"),
  PROOF_OF_DELIVERY(PKCSObjectIdentifiers.id_cti_ets_proofOfDelivery.getId(), "Proof of delivery"),
  PROOF_OF_SENDER(PKCSObjectIdentifiers.id_cti_ets_proofOfSender.getId(), "Proof of sender"),
  PROOF_OF_APPROVAL(PKCSObjectIdentifiers.id_cti_ets_proofOfApproval.getId(), "Proof of approval"),
  PROOF_OF_CREATION(PKCSObjectIdentifiers.id_cti_ets_proofOfCreation.getId(), "Proof of creation");
  // @formatter:on

  private final String id;

  private final String label;

  private ETSCommitmentType(final String id, final String label) {
    this.id = id;
    this.label = label;
  }

  public String getId() {
    return this.id;
  }

  @Override
  public String toString() {
    return this.label;
  }

}
