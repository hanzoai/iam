describe('Test User', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test user", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/users");
        cy.url().should("eq", "http://localhost:8000/users");
        cy.visit("http://localhost:8000/users/hanzo/z");
        cy.url().should("eq", "http://localhost:8000/users/hanzo/z");
    });
})
