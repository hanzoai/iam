describe('Test certs', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test certs", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/certs");
        cy.url().should("eq", "http://localhost:8000/certs");
        cy.visit("http://localhost:8000/certs/cert-hanzo");
        cy.url().should("eq", "http://localhost:8000/certs/cert-hanzo");
    });
})
