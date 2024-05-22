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
  if (!bearerToken || !bearerToken.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Please Provide a bearer token" });
  }
  const token = bearerToken.split(" ")[1];
  try {
    const { user } = await verifyToken(token);
    if (user.token) {
      req.user = user;
      return next();
    } else {
      return res.status(401).send({ message: "Token is invalid" });
    }
  } catch (err) {
    return res
      .status(401)
      .send({ message: "Please provide a valid bearer token" });
  }
}
module.exports = authenticate;
