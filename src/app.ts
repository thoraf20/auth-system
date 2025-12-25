import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import pinoHttp from "pino-http";
import authRoutes from "./routes/auth.routes";
import userRoutes from "./routes/user.routes"
import dashboardRoutes from "./routes/admin.routes"
import { createUserTable } from "./models/user.models";
import logger from "./utils/logger";
import { redisClient } from "./config/redis";


import { globalLimiter, authLimiter } from "./middlewares/rateLimit.middlewares";

dotenv.config();

const app = express();



app.use(pinoHttp({ logger: logger as any }));
app.use(express.json());

app.use(cors());
app.use(helmet());
app.use(globalLimiter);

app.use("/api/auth", authLimiter, authRoutes);
app.use("/api/user", userRoutes);
app.use("/api/admin", dashboardRoutes);


createUserTable().catch(err => logger.error({ err }, "Failed to initialize database"));

export default app;

