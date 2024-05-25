describe("Authentication API", () => {
  it("Signs up a new user", () => {
    cy.request("POST", "/api/signup", {
      first_name: "John",
      last_name: "Doe",
      email: "johsdn@example.com",
      password: "password123",
    }).then((response) => {
      expect(response.status).to.equal(201);
      expect(response.body).to.have.property("user");
      expect(response.body).to.have.property("token");
    });
  });

  it("Logs in an existing user", () => {
    cy.request("POST", "/api/login", {
      email: "john@example.com",
      password: "password123",
    }).then((response) => {
      expect(response.status).to.equal(200);
      expect(response.body).to.have.property("user");
      expect(response.body).to.have.property("token");
    });
  });
});
