const { app } = require("./src/server");
const connectDb = require("./src/config/db");

app.listen(process.env.PORT || 2233, async (req, res) => {
  console.log("Listening on port " + process.env.PORT || 2233);
  await connectDb();
});
