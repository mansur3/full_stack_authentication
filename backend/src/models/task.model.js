const mongoose = require("mongoose");
const { Schema } = mongoose;

const TaskSchema = new Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, required: true },
});

const taskModel = mongoose.model("Task", TaskSchema);

module.exports = taskModel;
