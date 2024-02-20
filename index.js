const express = require("express");
const app = express();
const port = 5000;
const jwt = require("jsonwebtoken");

const tokenTimeLimit = "30s";
// const refreshTokenTimeLimit = "24hrs";
const accessTokenSecret = "mySecretKey";
const refreshTokenSecret = "myRefreshSecretKey";

app.use(express.json());

// alternative of user database
const users = [
  {
    id: "1",
    username: "john",
    password: "John0908",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "Jane0908",
    isAdmin: false,
  },
];

const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, accessTokenSecret, {
    expiresIn: tokenTimeLimit,
  });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, refreshTokenSecret);
};

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    // Generate an access token and a refresh token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json("Username or password incorrect!");
  }
});

app.post("/api/refresh", (req, res) => {
  // take refresh token from user
  const refreshToken = req.body.token;

  // send error if there is no token or invalid token
  if (!refreshToken) return res.status(401).json("You are not authenticated!");

  // Verify the refresh token
  jwt.verify(refreshToken, refreshTokenSecret, (err, user) => {
    if (err) {
      return res.status(403).json("Refresh token is invalid");
    }

    // Generate a new access token
    const newAccessToken = generateAccessToken(user);

    // Send the new access token to the user
    res.status(200).json({
      accessToken: newAccessToken,
    });
  });
});

const verifyAccessToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, accessTokenSecret, (err, user) => {
      if (err) {
        return res.status(403).json("Invalid access token");
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};

app.delete("/api/users/:userId", verifyAccessToken, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("User has been deleted.");
  } else {
    res.status(403).json("You are not allowed to delete this user!");
  }
});

app.listen(port, () => console.log("Backend server is running!"));
