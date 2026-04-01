describe('Test webhooks', () => {
    beforeEach(()=>{
        cy.visit("http://localhost:8000");
        cy.login();
    })
    const selector = {
        add: ".ant-table-title > div > .ant-btn"
      };
    it("test webhooks", () => {

        cy.visit("http://localhost:8000/webhooks");
        cy.url().should("eq", "http://localhost:8000/webhooks");
        cy.get(selector.add,{timeout:10000}).click();
        cy.url().should("include","http://localhost:8000/webhooks/");
    });
})
