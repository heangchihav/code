require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const app = express();

app.use(express.json());

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

//----------------------------starter------------------------------------//

// Helper function to generate a new access token
const generateAccessToken = (user) => {
  return jwt.sign({ userId: user.id }, ACCESS_TOKEN_SECRET, {
    expiresIn: "15m",
  });
};

// Helper function to hash refresh token
const hashToken = (token) => {
  return bcrypt.hashSync(token, 10);
};

// Register route
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);

  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    res.status(201).json({ message: "User created", userId: user.id });
  } catch (error) {
    res.status(400).json({ message: "Error creating user" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign({ userId: user.id }, REFRESH_TOKEN_SECRET);
    const hashedRefreshToken = hashToken(refreshToken);

    await prisma.refreshToken.create({
      data: {
        userId: user.id,
        hashedToken: hashedRefreshToken,
      },
    });

    // For web clients, set the refresh token in a secure cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true, // set to true if using https
      sameSite: "Strict", // adjust according to your needs
    });

    // For mobile clients, send the refresh token in the response body
    // The mobile app should handle storing this token securely
    res.json({
      accessToken, // for both web and mobile
      refreshToken: req.body.isMobile ? refreshToken : undefined, // only send if the client is mobile
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in" });
  }
});

// Token refresh route
app.post("/refresh", async (req, res) => {
  const { token } = req.body || req.cookies;
  if (!token) {
    return res.status(401).json({ message: "Refresh token required" });
  }

  try {
    const refreshToken = await prisma.refreshToken.findFirst({
      where: {
        hashedToken: hashToken(token),
        revoked: false,
      },
    });

    if (!refreshToken) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }
    ///////////////////////////////////////////
    const verified = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const accessToken = generateAccessToken({ id: verified.userId });

    await prisma.refreshToken.update({
      where: { id: refreshToken.id },
      data: { revoked: true },
    });

    const newRefreshToken = jwt.sign(
      { userId: verified.userId },
      REFRESH_TOKEN_SECRET
    );
    const hashedNewRefreshToken = hashToken(newRefreshToken);

    await prisma.refreshToken.create({
      data: {
        userId: verified.userId,
        hashedToken: hashedNewRefreshToken,
      },
    });

    // For web clients, set the refresh token in a secure cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true, // set to true if using https
      sameSite: "Strict", // adjust according to your needs
    });

    // For mobile clients, send the refresh token in the response body
    // The mobile app should handle storing this token securely
    res.json({
      accessToken, // for both web and mobile
      refreshToken: req.body.isMobile ? newRefreshToken : undefined, // only send if the client is mobile
    });
  } catch (error) {
    res.status(500).json({ message: "Error refreshing token" });
  }
});

// Middleware to authenticate access token
const authenticateAccessToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Protected route
app.get("/protected", authenticateAccessToken, (req, res) => {
  res.json({ message: "Protected content accessed" });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
