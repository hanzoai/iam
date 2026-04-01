describe('Test records', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test records", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/records");
        cy.url().should("eq", "http://localhost:8000/records");
    });
})
