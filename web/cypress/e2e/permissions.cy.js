describe('Test permissions', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test permissions", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/permissions");
        cy.url().should("eq", "http://localhost:8000/permissions");
        cy.visit("http://localhost:8000/permissions/hanzo/permission-hanzo");
        cy.url().should("eq", "http://localhost:8000/permissions/hanzo/permission-hanzo");
    });
})
