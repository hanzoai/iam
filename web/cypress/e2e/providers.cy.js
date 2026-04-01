describe('Test providers', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test providers", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/providers");
        cy.url().should("eq", "http://localhost:8000/providers");
        cy.visit("http://localhost:8000/providers/admin/provider_captcha_default");
        cy.url().should("eq", "http://localhost:8000/providers/admin/provider_captcha_default");
    });
})
