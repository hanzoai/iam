describe('Test sessions', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test sessions", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/sessions");
        cy.url().should("eq", "http://localhost:8000/sessions");
    });
})
