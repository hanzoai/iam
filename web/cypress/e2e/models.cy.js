describe('Test models', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test org", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/models");
        cy.url().should("eq", "http://localhost:8000/models");
        cy.visit("http://localhost:8000/models/hanzo/model-hanzo");
        cy.url().should("eq", "http://localhost:8000/models/hanzo/model-hanzo");
    });
})
