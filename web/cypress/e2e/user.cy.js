describe('Test User', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test user", () => {
        cy.visit("http://localhost:7001");
        cy.visit("http://localhost:7001/users");
        cy.url().should("eq", "http://localhost:7001/users");
        cy.visit("http://localhost:7001/users/hanzo/z");
        cy.url().should("eq", "http://localhost:7001/users/hanzo/z");
    });
})
