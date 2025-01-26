import express from "express";
import { forgotPassword, login, register, resetPassword } from "../controllers/auth.controllers";
import { authenticate } from "../middlewares/auth.middlewares";
import { updateProfile } from "../controllers/user.controller";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);

// Profile Update Route (protected)
router.put('/profile', authenticate, updateProfile);

export default router;
