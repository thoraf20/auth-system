import express from "express";
import { authenticate } from "../middlewares/auth.middleware";
import { getUserProfile } from "../controllers/user.controller";

const router = express.Router();

router.get("/profile", authenticate, getUserProfile); // Protected route

export default router;
