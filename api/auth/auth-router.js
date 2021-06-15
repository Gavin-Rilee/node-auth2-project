const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");

router.post("/register", validateRoleName, async (req, res, next) => {
  const user = req.body;
  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds);
  user.password = hash;
  Users.add(user)
    .then((user) => {
      res.status(201).json(user);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  let { password } = req.body;
  const user = req.user;
  if (user && bcrypt.compareSync(password, user.password)) {
    const token = tokenBuilder(user);
    res.json({
      message: `${user.username} is back!`,
      token: token,
    });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
});

function tokenBuilder(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const config = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, config);
}

module.exports = router;
