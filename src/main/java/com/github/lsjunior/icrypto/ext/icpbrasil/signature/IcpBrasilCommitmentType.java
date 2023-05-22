package com.github.lsjunior.icrypto.ext.icpbrasil.signature;

import com.github.lsjunior.icrypto.api.type.ETSCommitmentType;

public enum IcpBrasilCommitmentType {

  // @formatter:off
  // ETS
  COMPROVACAO_ORIGEM(ETSCommitmentType.PROOF_OF_ORIGIN.getId(), "Comprovação de origem"),
  COMPROVACAO_RECEBIMENTO(ETSCommitmentType.PROOF_OF_RECEIPT.getId(), "Comprovação de recebimento"),
  COMPROVACAO_ENTREGA(ETSCommitmentType.PROOF_OF_DELIVERY.getId(),"Comprovação de entrega"),
  COMPROVACAO_ENVIO(ETSCommitmentType.PROOF_OF_SENDER.getId(), "Comprovação de envio"),
  COMPROVACAO_APROVACAO(ETSCommitmentType.PROOF_OF_APPROVAL.getId(), "Comprovação de aprovação"),
  COMPROVACAO_CRIACAO(ETSCommitmentType.PROOF_OF_CREATION.getId(), "Comprovação de criação"),
  // ICP
  CONCORDANCIA("2.16.76.1.8.1", "Concordância"),
  AUTORIZACAO("2.16.76.1.8.2", "Autorização"),
  TESTEMUNHO("2.16.76.1.8.3", "Testemunho"),
  AUTORIA("2.16.76.1.8.4", "Autoria"),
  CONFERENCIA("2.16.76.1.8.5", "Conferência"),
  REVISAO("2.16.76.1.8.6", "Revisão"),
  CIENCIA("2.16.76.1.8.7", "Ciência"),
  PUBLICACAO("2.16.76.1.8.8", "Publicação"),
  TESTE("2.16.76.1.8.12", "Teste");
  // @formatter:on

  private String id;

  private String label;

  private IcpBrasilCommitmentType(final String id, final String label) {
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
