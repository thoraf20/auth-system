import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import { redisClient } from "../config/redis";
import logger from "../utils/logger";

const createStore = () => {
  if (process.env.REDIS_ENABLED === "true" || redisClient.isOpen) {
    logger.info("Using Redis Store for rate limiting");
    return new RedisStore({
      sendCommand: (...args: string[]) => redisClient.sendCommand(args),
    });
  }
  logger.warn("Redis is not connected. Falling back to MemoryStore for rate limiting.");
  return undefined; // Falls back to internal MemoryStore
};

// Global rate limiter
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
  message: "Too many requests from this IP, please try again after 15 minutes",
  standardHeaders: true,
  legacyHeaders: false,
  store: createStore(),
});

// Stricter rate limiter for auth endpoints
export const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: "Too many authentication attempts, please try again after an hour",
  standardHeaders: true,
  legacyHeaders: false,
  store: createStore(),
});


