describe("Task routes", () => {
  it("should create a new task", () => {
    cy.request({
      method: "POST",
      url: "/api/task/create-task",
      body: {
        title: "Test Task",
        description:
          "Test Take me down to the river end. Take me down the fighting end. Wash the poison from of my skin. Show me how to be whole again. Fly me up in the novice glow. Drop me down to the dream below.",
        status: "To Do",
      },
      headers: {
        Authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbkRhdGEiOnsiX2lkIjoiNjY0ZjY2NTZkMzE1YmI3YjQ5MDJkYTQ2IiwiZmlyc3RfbmFtZSI6ImZpcnN0IiwibGFzdF9uYW1lIjoibmFtZSIsImVtYWlsIjoiZW1haTJnbWFpbEBnbWFpbC5jb20iLCJwYXNzd29yZCI6IiQyYiQwOCRGRnlEcExDWDdsa2w2SWNXMWVHZDh1UGdjb25tMWFLODRwSjV5SGJVaTJnQ0Z6VGlQTTJObSIsImNvdW50cnkiOiJDQSIsInBob25lX251bWJlciI6IjgyNTAyNDg5OTEiLCJjcmVhdGVkQXQiOiIyMDI0LTA1LTIzVDE1OjUyOjU0LjQ3MFoiLCJ1cGRhdGVkQXQiOiIyMDI0LTA1LTIzVDE1OjUyOjU0LjQ3MFoifSwiaWF0IjoxNzE2NjE2NzkyLCJleHAiOjE3MTcyMjE1OTJ9.9sav6xmQt9clYsOo3xBpt2ypFnCv0JLRYkd4wNMGHIg", // Add your authorization token if required
      },
    }).then((response) => {
      expect(response.status).to.equal(201);
      expect(response.body.message).to.equal("created");
      expect(response.body.data).to.have.property("title", "Test Task");
    });
  });

  it("should retrieve all tasks", () => {
    cy.request({
      method: "GET",
      url: "/api/task/tasks",
      headers: {
        Authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbkRhdGEiOnsiX2lkIjoiNjY0ZjY2NTZkMzE1YmI3YjQ5MDJkYTQ2IiwiZmlyc3RfbmFtZSI6ImZpcnN0IiwibGFzdF9uYW1lIjoibmFtZSIsImVtYWlsIjoiZW1haTJnbWFpbEBnbWFpbC5jb20iLCJwYXNzd29yZCI6IiQyYiQwOCRGRnlEcExDWDdsa2w2SWNXMWVHZDh1UGdjb25tMWFLODRwSjV5SGJVaTJnQ0Z6VGlQTTJObSIsImNvdW50cnkiOiJDQSIsInBob25lX251bWJlciI6IjgyNTAyNDg5OTEiLCJjcmVhdGVkQXQiOiIyMDI0LTA1LTIzVDE1OjUyOjU0LjQ3MFoiLCJ1cGRhdGVkQXQiOiIyMDI0LTA1LTIzVDE1OjUyOjU0LjQ3MFoifSwiaWF0IjoxNzE2NjE2NzkyLCJleHAiOjE3MTcyMjE1OTJ9.9sav6xmQt9clYsOo3xBpt2ypFnCv0JLRYkd4wNMGHIg", // Add your authorization token if required
      },
    }).then((response) => {
      expect(response.status).to.equal(200);
      expect(response.body.data).to.be.an("array");
    });
  });
  it("Should update specific task", () => {
    cy.request({
      method: "PATCH",
      url: "api/task/task/664f7600a26eb4eb55beb1f3",
      headers: {
        Authorization:
          "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbkRhdGEiOnsiX2lkIjoiNjY0ZjY2NTZkMzE1YmI3YjQ5MDJkYTQ2IiwiZmlyc3RfbmFtZSI6ImZpcnN0IiwibGFzdF9uYW1lIjoibmFtZSIsImVtYWlsIjoiZW1haTJnbWFpbEBnbWFpbC5jb20iLCJwYXNzd29yZCI6IiQyYiQwOCRGRnlEcExDWDdsa2w2SWNXMWVHZDh1UGdjb25tMWFLODRwSjV5SGJVaTJnQ0Z6VGlQTTJObSIsImNvdW50cnkiOiJDQSIsInBob25lX251bWJlciI6IjgyNTAyNDg5OTEiLCJjcmVhdGVkQXQiOiIyMDI0LTA1LTIzVDE1OjUyOjU0LjQ3MFoiLCJ1cGRhdGVkQXQiOiIyMDI0LTA1LTIzVDE1OjUyOjU0LjQ3MFoifSwiaWF0IjoxNzE2NjE2NzkyLCJleHAiOjE3MTcyMjE1OTJ9.9sav6xmQt9clYsOo3xBpt2ypFnCv0JLRYkd4wNMGHIg", // Add your authorization token if required
      },
      body: {
        title: "Test Task",
        description:
          "Test Take me down to the river end. Take me down the fighting end. Wash the poison from of my skin. Show me how to be whole again. Fly me up in the novice glow. Drop me down to the dream below.",
        status: "To Do",
      },
    }).then((response) => {
      expect(response.status).to.equal(200);
    });
  });
});
