resource "azurerm_postgresql_flexible_server" "ledger" {
  name     = "ledger-prod"
  location = "westeurope"
}

resource "azurerm_role_assignment" "deployer" {
  scope                = azurerm_postgresql_flexible_server.ledger.id
  role_definition_name = "Contributor"
  principal_id         = var.deployer_principal_id
}
