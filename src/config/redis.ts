import { createClient } from "redis";
import logger from "../utils/logger";

const redisClient = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
});

redisClient.on("error", (err) => logger.error({ err }, "Redis Client Error"));
redisClient.on("connect", () => logger.info("Redis Client Connected"));

// Connect immediately
redisClient.connect().catch((err) => {
  logger.error({ err }, "Could not connect to Redis at startup");
});

export { redisClient };

