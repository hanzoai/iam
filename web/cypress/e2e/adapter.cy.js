describe('Test adapter', () => {
    beforeEach(()=>{
        cy.login();
    })
    const selector = {
        add: ".ant-table-title > div > .ant-btn"
      };
    it("test adapter", () => {
        cy.visit("http://localhost:8000/adapters");
        cy.url().should("eq", "http://localhost:8000/adapters");
        cy.get(selector.add,{timeout:15000}).should('be.visible').click({force:true});
        cy.url().should("include","http://localhost:8000/adapters/hanzo/")
    });
})
