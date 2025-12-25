import express from "express";
import { authenticate } from "../middlewares/auth.middlewares";
import { authorize } from "../middlewares/role.middlewares";

const router = express.Router();

router.get("/dashboard", authenticate, authorize(["admin"]), (req, res) => {
  res.json({ message: "Welcome to the admin dashboard" });
});

export default router;
