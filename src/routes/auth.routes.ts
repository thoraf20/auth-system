import express from "express";
import { 
  forgotPassword, 
  login, 
  register, 
  resetPassword, 
  refreshToken, 
  logout, 
  verifyEmail, 
  changePassword,
  setup2FA,
  verify2FA,
  authenticate2FA
} from "../controllers/auth.controllers";
import { authenticate } from "../middlewares/auth.middlewares";
import { updateProfile } from "../controllers/user.controller";

const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refreshToken);
router.post("/logout", logout);
router.get("/verify-email/:token", verifyEmail);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);
router.post("/change-password", authenticate, changePassword);

router.post("/2fa/setup", authenticate, setup2FA);
router.post("/2fa/verify", authenticate, verify2FA);
router.post("/2fa/authenticate", authenticate2FA);

router.put('/profile', authenticate, updateProfile);

export default router;
