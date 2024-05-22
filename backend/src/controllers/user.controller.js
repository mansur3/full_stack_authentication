const express = require("express");
const router = express.Router();
require("dotenv").config();
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const User = require("../models/user.models");

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

module.exports = router;
