import { Router } from "express";
import {
  refreshAccessToken,
  signIn,
  signOut,
  signUp,
} from "../controllers/authController";

const router = Router();

router.post("/sign-in", signIn);
router.post("/sign-up", signUp);
router.post("/refresh-token", refreshAccessToken);
router.post("/sign-out", signOut);

export default router;
