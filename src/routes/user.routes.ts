import express from "express";
import { authenticate } from "../middlewares/auth.middlewares";
import { getUserProfile } from "../controllers/user.controller";

const router = express.Router();

router.get("/profile", authenticate, getUserProfile);

export default router;
