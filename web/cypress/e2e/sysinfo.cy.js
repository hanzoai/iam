describe('Test sysinfo', () => {
    beforeEach(()=>{
        cy.login();
    })
    it("test sysinfo", () => {
        cy.visit("http://localhost:8000");
        cy.visit("http://localhost:8000/sysinfo");
        cy.url().should("eq", "http://localhost:8000/sysinfo");
    });
})
