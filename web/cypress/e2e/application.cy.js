describe('Test aplication', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test aplication", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/applications");
        cy.url().should("eq", "http://localhost:8000/applications");
        cy.visit("http://localhost:8000/applications/hanzo/hanzo-app");
        cy.url().should("eq", "http://localhost:8000/applications/hanzo/hanzo-app");
    });
})
