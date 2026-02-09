describe('Test Orgnazition', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test org", () => {
        cy.visit("http://localhost:7001");
        cy.visit("http://localhost:7001/organizations");
        cy.url().should("eq", "http://localhost:7001/organizations");
        cy.visit("http://localhost:7001/organizations/hanzo");
        cy.url().should("eq", "http://localhost:7001/organizations/hanzo");
        cy.visit("http://localhost:7001/organizations/hanzo/users");
        cy.url().should("eq", "http://localhost:7001/organizations/hanzo/users");
    });
})
