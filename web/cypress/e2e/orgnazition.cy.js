describe('Test Orgnazition', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test org", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/organizations");
        cy.url().should("eq", "http://localhost:8000/organizations");
        cy.visit("http://localhost:8000/organizations/hanzo");
        cy.url().should("eq", "http://localhost:8000/organizations/hanzo");
        cy.visit("http://localhost:8000/organizations/hanzo/users");
        cy.url().should("eq", "http://localhost:8000/organizations/hanzo/users");
    });
})
