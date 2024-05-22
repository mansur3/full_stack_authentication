const express = require("express");
const router = express.Router();

const { body, validationResult } = require("express-validator");
const Task = require("../models/task.model");
const authenticate = require("../middlewares/authenticate");

//create
router.post(
  "/create-task",
  authenticate,
  body("title")
    .isLength({ min: 5, max: 100 })
    .withMessage("title is required and must be between 5 and 100 characters"),
  body("description")
    .isLength({ min: 20, max: 300 })
    .withMessage("description is required and must be between 20 and 300"),
  body("status").notEmpty().withMessage("status is required"),
  async (req, res) => {
    let task;
    const errors = validationResult(req);
    let finalErrors = errors;
    if (!errors.isEmpty()) {
      finalErrors = errors.array().map((err) => {
        return {
          param: err.param,
          msg: err.msg,
        };
      });
      return res.status(422).send({
        errors: finalErrors,
      });
    }
    try {
      task = await Task.create(req.body);
      return res.status(201).send({
        message: "created",
        data: task,
      });
    } catch (err) {
      return res.status(500).send({
        message: err.toString(),
      });
    }
  }
);

//read
router.get("/tasks", authenticate, async (req, res) => {
  try {
    let tasks = Task.find().lean().exec();
    return res.status(200).send({
      data: tasks,
    });
  } catch (err) {
    return res.status(500).send({
      message: err.toString(),
    });
  }
});

router.get("/task/:id", authenticate, async (req, res) => {
  try {
    const id = req.params.id;

    const task = Task.findById(id);
    if (!task) {
      return res.status(404).send({
        message: "Task is not found.",
      });
    }
    return res.status(200).send({
      data: task,
    });
  } catch (err) {
    return res.status(500).send({
      message: err.toString(),
    });
  }
});
//update

router.patch("/task/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const task = Task.findByIdAndUpdate(id, req.body);
    if (!task) {
      return res.status(404).send({
        message: "Task is not found.",
      });
    }
    return res.status(200).send({
      message: "updated",
      data: task,
    });
  } catch (err) {
    return res.status(500).send({
      message: err.toString(),
    });
  }
});

//delete

router.delete("/task/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const task = Task.findByIdAndDelete(id);
    if (!task) {
      return res.status(404).send({
        message: "Task is not found",
      });
    }
    return res.status(200).send({
      message: "deleted",
      data: task,
    });
  } catch (err) {
    return res.status(500).send({
      message: err.toString(),
    });
  }
});

module.exports = router;
