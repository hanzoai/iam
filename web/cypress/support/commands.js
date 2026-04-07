const selector = {
  username: "#input",
  password: "#normal_login_password",
  loginButton: ".login-button",
};
Cypress.Commands.add('login', ()=>{
  // Use API login to avoid UI timing issues
  cy.request({
    method: 'POST',
    url: 'http://localhost:8000/api/login',
    body: {
      application: "app-built-in",
      organization: "built-in",
      username: "admin",
      password: "123",
      type: "code",
      signinMethod: "Password",
    },
  }).then((resp) => {
    expect(resp.status).to.eq(200);
  });
  cy.visit("http://localhost:8000");
})
