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
  // After login, the admin dashboard loads. Wait for any admin nav element
  // or the URL to change from the login page.
  cy.get(".ant-layout-sider, .ant-menu, [class*='Dashboard']", {timeout: 15000}).should("exist");
})
