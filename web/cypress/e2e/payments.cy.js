describe('Test payments', () => {
    beforeEach(()=>{
        cy.login();
    })
    const selector = {
        add: ".ant-table-title > div > .ant-btn"
      };
    it("test payments", () => {
        cy.visit("http://localhost:8000/payments");
        cy.url().should("eq", "http://localhost:8000/payments");
        cy.get(selector.add,{timeout:10000}).should('be.visible').click({force:true});
        cy.url().should("include","http://localhost:8000/payments/")
    });
})
