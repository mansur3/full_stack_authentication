const express = require("express");
const router = express.Router();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const User = require("../models/user.models");
const authenticate = require("../middlewares/authenticate");
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Specify the destination directory
  },
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    ); // Rename the file if needed
  },
});

// Initialize Multer with the storage configuration
const upload = multer({ storage: storage });

const jwtSecretKey = process.env.JWT_SECRET_KEY;

const newToken = async (user) => {
  const tokenData = user;
  let token = jwt.sign({ tokenData }, jwtSecretKey, {
    expiresIn: "7d",
  });
  return token;
};

router.post(
  "/signup",
  body("first_name")
    .isLength({ min: 2, max: 30 })
    .withMessage(
      "first_name is required and must be between 2 and 30 characters"
    ),
  body("last_name")
    .isLength({ min: 2, max: 30 })
    .withMessage(
      "last_name is required and must be between 2 and 30 characters"
    ),
  body("email").isEmail().withMessage("Email is required"),
  body("password")
    .isLength({ min: 8, max: 20 })
    .withMessage("Password must be at least 8 characters"),

  async (req, res) => {
    const errors = validationResult(req);
    let user;
    let finalErrors = null;
    if (!errors.isEmpty()) {
      finalErrors = errors.array().map((err) => {
        return {
          param: err.param,
          msg: err.msg,
        };
      });
      return res.status(422).json({
        errors: finalErrors,
      });
    }
    try {
      user = await User.findOne({ email: req.body.email });
      if (user) {
        return res.status(400).send({
          message: "User is already  exist",
        });
      }
      user = await User.create(req.body);
      let token = await newToken(user);
      return res.status(201).send({
        user,
        token,
      });
    } catch (err) {
      return res.status(500).send({
        message: err.toString(),
      });
    }
  }
);

router.post(
  "/login",
  body("email").isEmail().withMessage("required and email must be valid"),
  body("password").isString().withMessage("password required"),
  async (req, res) => {
    let user;
    const errors = validationResult(req);
    let finalErrors = null;
    if (!errors.isEmpty()) {
      finalErrors = errors.array().map((err) => {
        return {
          param: err.param,
          msg: err.msg,
        };
      });
      return res.status(422).json({
        errors: finalErrors,
      });
    }
    try {
      user = await User.findOne({ email: req.body.email });
      if (!user) {
        return res.status(400).send({
          message: "User is not found",
        });
      }
      let match = user.checkPassword(req.body.password);
      if (!match) {
        return res.status(400).send({
          message: "Password is incorrect",
        });
      }
      const token = await newToken(user);
      return res.status(200).json({
        user,
        token,
      });
    } catch (err) {
      return res.status(500).send({
        message: err.toString(),
      });
    }
  }
);

router.get("/user", authenticate, async (req, res) => {
  // const id = req.param.id;
  // console.log(req.user);
  const id = req.user._id;
  try {
    const user = await User.findOne({ _id: id });
    if (!user) {
      return res.status(404).send({
        message: "User is not found",
      });
    }
    return res.status(200).send({
      message: "success",
      data: user,
    });
  } catch (err) {
    return res.status(500).send({
      message: err.toString(),
    });
  }
});

router.post(
  "/profile/:id",
  authenticate,
  upload.single("avatar"),
  async (req, res) => {
    try {
      const user = await User.findByIdAndUpdate(
        { _id: req.params.id },
        { profile: req.file?.path },
        {
          new: true,
          runValidators: true,
        }
      );
      if (!user) {
        return res.status(404).send({
          message: "User is not found.",
        });
      }
      return res.status(200).send({
        messsage: "success",
        data: user,
      });
    } catch (err) {
      return res.status(500).send({
        message: err.toString(),
      });
    }
  }
);

router.patch("/user/:id", async (req, res) => {
  const id = req.params.id;
  try {
    const user = await User.findByIdAndUpdate({ _id: id }, req.body, {
      new: true,
      runValidators: true,
    });
    if (!user) {
      return res.status(404).send({
        message: "user is not found.",
      });
    }
    return res.status(200).send({
      message: "Updated",
      data: user,
    });
  } catch (err) {
    return res.status(500).send({
      message: err.toString(),
    });
  }
});

module.exports = router;
