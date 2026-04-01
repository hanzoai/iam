describe('Test roles', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test role", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/roles");
        cy.url().should("eq", "http://localhost:8000/roles");
    });
})
