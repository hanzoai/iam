describe('Test resource', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test resource", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/resources");
        cy.url().should("eq", "http://localhost:8000/resources");
    });
})
