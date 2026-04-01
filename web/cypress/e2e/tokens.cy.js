describe('Test tokens', () => {
    beforeEach(()=>{
        cy.login();
    })
    const selector = {
        add: ".ant-table-title > div > .ant-btn"
      };
    it("test records", () => {
        cy.visit("http://localhost:8000/tokens");
        cy.url().should("eq", "http://localhost:8000/tokens");
        cy.get(selector.add,{timeout:10000}).click();
        cy.url().should("include","http://localhost:8000/tokens/")
    });
})
