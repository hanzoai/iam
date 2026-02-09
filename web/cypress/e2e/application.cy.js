describe('Test aplication', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test aplication", () => {
        cy.visit("http://localhost:7001");
        cy.visit("http://localhost:7001/applications");
        cy.url().should("eq", "http://localhost:7001/applications");
        cy.visit("http://localhost:7001/applications/hanzo/app-hanzo");
        cy.url().should("eq", "http://localhost:7001/applications/hanzo/app-hanzo");
    });
})
