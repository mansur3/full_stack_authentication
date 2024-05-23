const jwt = require("jsonwebtoken");
require("dotenv").config();

function verifyToken(token) {
  return new Promise(function (resolve, reject) {
    jwt.verify(
      token,
      process.env.JWT_SECRET_KEY,
      //   { algorithms: ["RS256"] },
      function (err, user) {
        if (err) return reject(err);

        return resolve(user);
      }
    );
  });
}

async function authenticate(req, res, next) {
  const bearerToken = req.headers.authorization;
  const check = !bearerToken || !bearerToken.startsWith("Bearer ");
  if (check) {
    return res.status(401).send({ message: "Please Provide a bearer token" });
  }
  const token = bearerToken.split(" ")[1];
  try {
    const resp = await verifyToken(token);
    if (resp.tokenData) {
      req.user = resp.tokenData;
      return next();
    } else {
      return res.status(401).send({ message: "Token is invalid" });
    }
  } catch (err) {
    console.log(err);
    return res
      .status(401)
      .send({ message: "Please provide a valid bearer token" });
  }
}
module.exports = authenticate;
