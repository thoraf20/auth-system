import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { redisClient } from "../config/redis";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET as string;

// Extend Request object to include user data
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

// Authentication Middleware
export const authenticate = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) {
    res.status(401).json({ message: "Access denied. No token provided." });
    return;
  }

  try {
    // Check if token is blacklisted in Redis
    const isBlacklisted = await redisClient.get(`blacklist:${token}`);
    if (isBlacklisted) {
      res.status(401).json({ message: "Token has been revoked. Please log in again." });
      return;
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).json({ message: "Invalid or expired token." });
    return;
  }
};


