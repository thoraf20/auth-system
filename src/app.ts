import express from "express";
import cors from "cors";
import helmet from "helmet";
import dotenv from "dotenv";
import authRoutes from "./routes/auth.routes";
import userRoutes from "./routes/user.routes"
import { createUserTable } from "./models/user.models";

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet());

// Routes
app.use("/api/auth", authRoutes);
app.use("/user", userRoutes);


// Initialize Database
createUserTable();

export default app;
