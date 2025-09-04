import express from "express";
import { sendOtpForRegistration, verifyOtp, register, login, sendOtpForPasswordReset, verifyResetOtp, setNewPassword } from "../contollers/authController.js";

const router = express.Router();

router.post("/send-otp", sendOtpForRegistration); // Step 1: Send OTP
router.post("/verify-otp", verifyOtp); // Step 2: Verify OTP
router.post("/register", register); // Step 3: Register user
router.post("/login", login); // Step 4: Login
router.post("/send-reset-otp", sendOtpForPasswordReset);
router.post("/verify-rest-otp",verifyResetOtp)
router.post("/reset-password", setNewPassword);

export default router;
