import jwt from "jsonwebtoken";
import pool from "../config/db";
import dotenv from "dotenv";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import logger from "../utils/logger";
import { 
  comparePassword, 
  generateToken, 
  hashPassword, 
  generateAccessToken, 
  generateRefreshToken 
} from "../utils/auth.utils";

dotenv.config();

const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET || "refresh-secret";
const MFA_TOKEN_SECRET = process.env.MFA_TOKEN_SECRET || "mfa-secret";

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(401).json({ message: "User already exists" });
    }

    const hashedPassword = await hashPassword(password);
    const verificationToken = generateToken();

    const newUser = await pool.query(
      "INSERT INTO users (name, email, password, verification_token) VALUES ($1, $2, $3, $4) RETURNING *",
      [name, email, hashedPassword, verificationToken]
    );

    const user = newUser.rows[0];
    const accessToken = generateAccessToken({ id: user.id, email, role: user.role });
    const refreshToken = generateRefreshToken({ id: user.id });

    await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [refreshToken, user.id]);

    const verifyUrl = `http://localhost:3000/api/auth/verify-email/${verificationToken}`;
    logger.info({ email, userId: user.id }, `Verification Email simulated: ${verifyUrl}`);

    return res.status(201).json({
      message: "User registered successfully. Please verify your email.",
      accessToken,
      refreshToken,
      user: { id: user.id, name, email },
    });
  } catch (error) {
    logger.error({ error }, "Registration Error");
    return res.status(500).json({ message: "Server error" });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    
    if (rows.length === 0) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const user = rows[0];

    const validPassword = await comparePassword(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    if (!user.is_verified) {
      return res.status(401).json({ message: "Please verify your email before logging in" });
    }

    if (user.is_two_factor_enabled) {
      const mfaToken = jwt.sign({ id: user.id }, MFA_TOKEN_SECRET, { expiresIn: "5m" });
      logger.info({ userId: user.id }, "2FA challenge initiated");
      return res.status(200).json({
        message: "2FA_REQUIRED",
        mfaToken
      });
    }

    const accessToken = generateAccessToken({ id: user.id, role: user.role });
    const refreshToken = generateRefreshToken({ id: user.id });

    await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [refreshToken, user.id]);

    logger.info({ userId: user.id }, "User logged in successfully");

    return res.status(200).json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, role: user.role, email },
    });

  } catch (error) {
    logger.error({ error }, "Login Error");
    res.status(500).json({ message: "Server error" });
  }
};

export const setup2FA = async (req, res) => {
  const userId = req.user.id;
  try {
    const { rows } = await pool.query("SELECT email FROM users WHERE id = $1", [userId]);
    const user = rows[0];

    const secret = authenticator.generateSecret();
    const otpauth = authenticator.keyuri(user.email, "ScalableAuthSystem", secret);
    const qrCode = await QRCode.toDataURL(otpauth);

    await pool.query("UPDATE users SET two_factor_secret = $1 WHERE id = $2", [secret, userId]);

    logger.info({ userId }, "2FA setup initiated");
    res.json({ secret, qrCode });
  } catch (error) {
    logger.error({ error, userId }, "Failed to setup 2FA");
    res.status(500).json({ message: "Server error" });
  }
};

export const verify2FA = async (req, res) => {
  const { code } = req.body;
  const userId = req.user.id;
  try {
    const { rows } = await pool.query("SELECT two_factor_secret FROM users WHERE id = $1", [userId]);
    const secret = rows[0].two_factor_secret;

    const isValid = authenticator.check(code, secret);
    if (!isValid) return res.status(400).json({ message: "Invalid code" });

    await pool.query("UPDATE users SET is_two_factor_enabled = TRUE WHERE id = $1", [userId]);

    logger.info({ userId }, "2FA enabled for user");
    res.json({ message: "2FA enabled successfully" });
  } catch (error) {
    logger.error({ error, userId }, "Failed to verify 2FA");
    res.status(500).json({ message: "Server error" });
  }
};

export const authenticate2FA = async (req, res) => {
  const { mfaToken, code } = req.body;
  try {
    const decoded: any = jwt.verify(mfaToken, MFA_TOKEN_SECRET);
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [decoded.id]);
    const user = rows[0];

    const isValid = authenticator.check(code, user.two_factor_secret);
    if (!isValid) return res.status(400).json({ message: "Invalid code" });

    const accessToken = generateAccessToken({ id: user.id, role: user.role });
    const refreshToken = generateRefreshToken({ id: user.id });

    await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [refreshToken, user.id]);

    logger.info({ userId: user.id }, "2FA authentication successful");

    res.json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: { id: user.id, name: user.name, role: user.role, email: user.email }
    });
  } catch (error) {
    logger.error({ error }, "2FA authentication failed");
    res.status(401).json({ message: "Invalid or expired MFA token" });
  }
};

export const refreshToken = async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: "Refresh token required" });

  try {
    const decoded: any = jwt.verify(token, REFRESH_TOKEN_SECRET);
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1 AND refresh_token = $2", [decoded.id, token]);
    
    if (rows.length === 0) {
      return res.status(403).json({ message: "Invalid refresh token" });
    }

    const user = rows[0];
    const newAccessToken = generateAccessToken({ id: user.id, role: user.role });
    const newRefreshToken = generateRefreshToken({ id: user.id });

    await pool.query("UPDATE users SET refresh_token = $1 WHERE id = $2", [newRefreshToken, user.id]);

    logger.info({ userId: user.id }, "Token refreshed");
    res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    logger.error({ error }, "Refresh token failed");
    res.status(403).json({ message: "Invalid refresh token" });
  }
};

import { redisClient } from "../config/redis";

export const logout = async (req, res) => {
  const authHeader = req.header("Authorization");
  const accessToken = authHeader?.split(" ")[1];
  const { token: refreshToken } = req.body;

  try {
    // Blacklist access token in Redis for 1 hour (default expiry)
    if (accessToken) {
      await redisClient.set(`blacklist:${accessToken}`, "true", {
        EX: 3600, // 1 hour
      });
    }

    // Invalidate refresh token in DB
    await pool.query("UPDATE users SET refresh_token = NULL WHERE refresh_token = $1", [refreshToken]);
    
    logger.info({ accessToken: !!accessToken, refreshToken: !!refreshToken }, "User logged out and token blacklisted");
    res.json({ message: "Logged out successfully" });
  } catch (error) {
    logger.error({ error }, "Logout error");
    res.status(500).json({ message: "Server error" });
  }
};


export const verifyEmail = async (req, res) => {
  const { token } = req.params;
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE verification_token = $1", [token]);
    if (rows.length === 0) return res.status(400).json({ message: "Invalid verification token" });

    await pool.query("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE verification_token = $1", [token]);
    logger.info({ userId: rows[0].id }, "Email verified");
    res.json({ message: "Email verified successfully" });
  } catch (error) {
    logger.error({ error }, "Email verification error");
    res.status(500).json({ message: "Server error" });
  }
};

export const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.id;

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
    const user = rows[0];

    const validPassword = await comparePassword(oldPassword, user.password);
    if (!validPassword) return res.status(400).json({ message: "Invalid old password" });

    const hashedPassword = await hashPassword(newPassword);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, userId]);

    logger.info({ userId }, "Password changed successfully");
    res.json({ message: "Password changed successfully" });
  } catch (error) {
    logger.error({ error, userId }, "Password change failed");
    res.status(500).json({ message: "Server error" });
  }
};

export const forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const resetToken = generateToken();
    const resetTokenExpiry = Date.now() + 3600000;

    await pool.query(
      "UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3",
      [resetToken, resetTokenExpiry, email]
    );

    const resetUrl = `http://localhost:3000/api/auth/reset-password/${resetToken}`;
    logger.info({ email }, `Reset Email simulated: ${resetUrl}`);

    return res.status(200).json({ message: "Password reset email sent" });
  } catch (err) {
    logger.error({ err }, "Forgot password error");
    res.status(500).json({ message: "Server error" });
  }
};

export const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const { rows } = await pool.query(
      'SELECT * FROM users WHERE reset_token = $1 AND reset_token_expiry > $2',
      [token, Date.now()]
    );
    if (rows.length === 0) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    const hashedPassword = await hashPassword(newPassword)

    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expiry = NULL WHERE reset_token = $2',
      [hashedPassword, token]
    );

    logger.info({ userId: rows[0].id }, "Password reset successfully");
    return res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    logger.error({ err }, "Reset password error");
    res.status(500).json({ message: 'Server error' });
  }
};

