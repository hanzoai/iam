describe("Login test", () => {
  const selector = {
    username: "#input",
    password: "#normal_login_password",
    loginButton: ".login-button",
  };
  it("Login succeeded", () => {
    cy.request({
      method: "POST",
      url: "http://localhost:8000/api/login",
      body: {
        "application": "hanzo-app",
        "organization": "hanzo",
        "username": "admin",
        "password": "123",
        "autoSignin": true,
        "type": "login",
      },
    }).then((Response) => {
      expect(Response).property("body").property("status").to.equal("ok");
    });
  });
  it("ui Login succeeded", () => {
    cy.visit("http://localhost:8000");
    cy.get(selector.username, {timeout: 15000}).type("admin");
    cy.get(selector.password, {timeout: 15000}).type("123");
    cy.get(selector.loginButton).click();
    // After successful login, Casdoor redirects to the dashboard
    cy.url({timeout: 15000}).should("eq", "http://localhost:8000/");
  });

  it("Login failed", () => {
    cy.request({
      method: "POST",
      url: "http://localhost:8000/api/login",
      body: {
        "application": "hanzo-app",
        "organization": "hanzo",
        "username": "admin",
        "password": "1234",
        "autoSignin": true,
        "type": "login",
      },
    }).then((Response) => {
      expect(Response).property("body").property("status").to.equal("error");
    });
  });
  it("ui Login failed", () => {
    cy.visit("http://localhost:8000");
    cy.get(selector.username, {timeout: 15000}).type("admin");
    cy.get(selector.password, {timeout: 15000}).type("1234");
    cy.get(selector.loginButton).click();
    // Failed login should stay on the login page
    cy.url().should("include", "/login");
  });
});
