const express = require("express");
const app = express();
const bodyParser = require("body-parser");
require("dotenv").config();

const cors = require("cors");

app.use(cors({ origin: "*" }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.json());

app.use("/api", async (req, res) => {
  return res.status(200).send({
    message: "We;lcome to the worle.",
  });
});

//Authentication controller
const userController = require("./controllers/user.controller");
const taskController = require("./controllers/task.controller");

//API

app.use("/api", userController);
app.use("/api/task", taskController);

module.exports = { app };
