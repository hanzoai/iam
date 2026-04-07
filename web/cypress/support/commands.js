// ***********************************************
// This example commands.js shows you how to
// create various custom commands and overwrite
// existing commands.
//
// For more comprehensive examples of custom
// commands please read more here:
// https://on.cypress.io/custom-commands
// ***********************************************
//
//
// -- This is a parent command --
// Cypress.Commands.add('login', (email, password) => { ... })
//
//
// -- This is a child command --
// Cypress.Commands.add('drag', { prevSubject: 'element'}, (subject, options) => { ... })
//
//
// -- This is a dual command --
// Cypress.Commands.add('dismiss', { prevSubject: 'optional'}, (subject, options) => { ... })
//
//
// -- This will overwrite an existing command --
// Cypress.Commands.overwrite('visit', (originalFn, url, options) => { ... })
const selector = {
  username: "#input",
  password: "#normal_login_password",
  loginButton: ".login-button",
};
Cypress.Commands.add('login', ()=>{
  cy.visit("http://localhost:8000");
  cy.get(selector.username, {timeout: 15000}).type("admin");
  cy.get(selector.password, {timeout: 15000}).type("123");
  cy.get(selector.loginButton).click();
  cy.url({timeout: 15000}).should("not.include", "/login");
})
