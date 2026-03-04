import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// ✅ In-memory OTP storage (use Redis in production)
const otpStorage = new Map();

// ✅ Configure Nodemailer (Render safe SMTP settings)
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // MUST be Gmail App Password
  },
  tls: {
    rejectUnauthorized: false,
  },
});


// ✅ Generate a 4-digit OTP
const generateOTP = () => crypto.randomInt(1000, 9999).toString();

/** ✅ Step 1: Send OTP to Email */
export const sendOtpForRegistration = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const otp = generateOTP();
    console.log(`✅ Generated OTP for ${email}: ${otp}`);

    // ✅ Store OTP with 2-minute expiry
    otpStorage.set(email, { otp, expiresAt: Date.now() + 2 * 60 * 1000 });

    // ✅ Send OTP Email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your One-Time Password (OTP) Code",
      html: `
        <!DOCTYPE html>
        <html>

        <head>
          <meta charset="UTF-8" />
          <title>Travel World - OTP Verification</title>
        </head>

        <body style="margin:0; padding:0; background-color:#f2f2f2; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f2f2f2;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 4px 12px rgba(0,0,0,0.1);">

                  <!-- Header -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #d9534f, #c9302c); padding:35px 20px; text-align:center; color:#fff;">
                      <h1 style="font-size:28px; font-weight:900; margin:0;">🔐 OTP Verification</h1>
                      <h2 style="font-size:16px; font-weight:400; margin:8px 0 0;">Secure your account with Travel World</h2>
                    </td>
                  </tr>

                  <!-- OTP Content -->
                  <tr>
                    <td style="padding:30px; font-size:16px; color:#333;">
                      <p style="margin-bottom:15px;">Hi,</p>

                      <p style="margin-bottom:20px;">
                        Your One-Time Password (OTP) is:
                        <span style="display: inline-block; font-weight: bold; background-color: #d9534f; color: #ffffff; padding: 8px 14px; border-radius: 6px; font-size: 20px;">
                          ${otp}
                        </span>
                      </p>

                      <p style="margin-bottom:20px;">
                        ⏳ This code is valid for <br />
                        <span style="font-weight: bold; background-color: #fff3cd; color: #856404; padding: 4px 8px; border-radius: 4px;">
                          2 minutes
                        </span>
                        only.
                      </p>

                      <p style="margin-bottom:20px;">🔒 <strong>Do not share this code with anyone, including our support team.</strong></p>

                      <p style="margin-bottom:20px;">📌 Use this code to securely complete your action.</p>

                      <p>If you did not request this OTP, please ignore this message or contact our support team immediately.</p>

                      <p style="margin-top:30px;">Thank you,<br /><strong>Travel World Team</strong></p>
                    </td>
                  </tr>

                  <!-- Footer -->
                  <tr>
                    <td style="padding:20px; font-size:12px; text-align:center; color:#888;">
                      <hr style="border:0; border-top:1px solid #ddd; margin-bottom:15px;">
                      This is an official communication from <strong>Travel World</strong><br />
                      &copy; 2025 <strong>Travel World</strong> - Your Trusted Travel Partner<br />
                      📞 +91-6352342951 | <br/>✉️ <a href="mailto:travelworld2904@gmail.com" style="color:#d9534f; text-decoration:none;">travelworld2904@gmail.com</a>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log("✅ OTP Sent Successfully");

    res.status(200).json({ success: true, message: "OTP sent successfully" });

  } catch (error) {
    console.error("❌ Error sending OTP:", error);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};

/** ✅ Step 2: Verify OTP */
export const verifyOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    console.log(`🔍 Verifying OTP for email: ${email}`);

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are required" });
    }

    const storedOTP = otpStorage.get(email);

    if (!storedOTP) {
      return res.status(400).json({ success: false, message: "OTP expired or not found" });
    }

    // ✅ Check OTP expiration
    if (Date.now() > storedOTP.expiresAt) {
      otpStorage.delete(email);
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    // ✅ Verify OTP
    if (storedOTP.otp !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    console.log("✅ OTP Verified Successfully");

    // ✅ Mark OTP as verified (prevent reuse)
    otpStorage.set(email, { verified: true });

    res.status(200).json({ success: true, message: "OTP verified successfully" });

  } catch (error) {
    console.error("❌ OTP Verification Error:", error);
    res.status(500).json({ success: false, message: "Failed to verify OTP" });
  }
};

/** ✅ Step 3: Register User (After OTP Verification) */
export const register = async (req, res) => {
  try {
    const { username, email, password, role, photo } = req.body;

    // ✅ Ensure OTP was verified
    const otpStatus = otpStorage.get(email);
    if (!otpStatus || !otpStatus.verified) {
      return res.status(400).json({ success: false, message: "OTP verification required" });
    }

    // ✅ Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "User already registered" });
    }

    // ✅ Hash password
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    // ✅ Create and save user
    const newUser = new User({
      username,
      email,
      password: hash,
      role,
      photo,
    });

    await newUser.save();

    // ✅ Clean up OTP
    otpStorage.delete(email);

    res.status(200).json({ success: true, message: "Successfully registered" });

  } catch (error) {
    console.error("❌ Registration Error:", error);
    res.status(500).json({ success: false, message: "Failed to register. Try again." });
  }
};

/** ✅ Step 4: Login User */
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ Check if user exists
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // ✅ Validate password
    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(401).json({ success: false, message: "Incorrect Email or Password" });
    }

    // ✅ Remove password before sending response
    const { password: hashedPassword, role, ...rest } = user._doc;

    // ✅ Generate JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET_KEY,
      { expiresIn: "15d" }
    );

    res.status(200).json({
      success: true,
      token,
      data: { ...rest },
      role,
    });

  } catch (error) {
    console.error("❌ Login Error:", error);
    res.status(500).json({ success: false, message: "Failed to login" });
  }
};

/** Step 1: Send OTP for Password Reset */
export const sendOtpForPasswordReset = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, message: "Email is required" });
    }

    const normalizedEmail = email.toLowerCase();

    // ✅ Check if user exists
    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // ✅ Generate and store OTP
    const otp = generateOTP();
    console.log(`✅ Password Reset OTP for ${normalizedEmail}: ${otp}`);

    otpStorage.set(normalizedEmail, { otp, expiresAt: Date.now() + 2 * 60 * 1000 }); // 2 min expiry

    // ✅ Send OTP via Email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: normalizedEmail,
      subject: "Password Reset OTP - Travel World",
      html: `
<!DOCTYPE html>
<html>

<head>
  <meta charset="UTF-8" />
  <title>Travel World - Password Reset OTP</title>
</head>

<body style="margin:0; padding:0; background-color:#f2f2f2; font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f2f2f2;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:10px; overflow:hidden; box-shadow:0 4px 12px rgba(0,0,0,0.1);">

          <!-- Header -->
          <tr>
            <td style="background: linear-gradient(135deg, #d9534f, #c9302c); padding:35px 20px; text-align:center; color:#fff;">
              <h1 style="font-size:28px; font-weight:900; margin:0;">🔑 Password Reset OTP</h1>
              <h2 style="font-size:16px; font-weight:400; margin:8px 0 0;">Secure your Travel World account</h2>
            </td>
          </tr>

          <!-- OTP Content -->
          <tr>
            <td style="padding:30px; font-size:16px; color:#333;">
              <p style="margin-bottom:15px;">Hi,</p>

              <p style="margin-bottom:20px;">
                Your OTP for password reset is:
                <span style="display:inline-block; font-weight:bold; background-color:#d9534f; color:#ffffff; padding:8px 14px; border-radius:6px; font-size:20px;">
                  ${otp}
                </span>
              </p>

              <p style="margin-bottom:20px;">
                ⏳ This code is valid for <br />
                <span style="font-weight:bold; background-color:#fff3cd; color:#856404; padding:4px 8px; border-radius:4px;">
                  2 minutes
                </span>
                only.
              </p>

              <p style="margin-bottom:20px;">🔒 <strong>Do not share this OTP with anyone.</strong></p>

              <p style="margin-bottom:20px;">If you did not request this password reset, please ignore this email.</p>

              <p style="margin-top:30px;">Thank you,<br /><strong>Travel World Team</strong></p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding:20px; font-size:12px; text-align:center; color:#888;">
              <hr style="border:0; border-top:1px solid #ddd; margin-bottom:15px;">
              This is an official communication from <strong>Travel World</strong><br />
              &copy; 2025 <strong>Travel World</strong> - Your Trusted Travel Partner<br />
              📞 +91-6352342951 | <br/>
              ✉️ <a href="mailto:travelworld2904@gmail.com" style="color:#d9534f; text-decoration:none;">travelworld2904@gmail.com</a>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`
    });

    return res.status(200).json({
      success: true,
      message: "Password reset OTP sent successfully",
    });

  } catch (error) {
    console.error("❌ Error sending reset OTP:", error);
    return res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
};


/** Step 2: Verify OTP */
export const verifyResetOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are required" });
    }

    const normalizedEmail = email.toLowerCase();
    const storedData = otpStorage.get(normalizedEmail);

    if (!storedData) {
      return res.status(400).json({ success: false, message: "OTP expired or not found" });
    }

    // ✅ Check expiry
    if (Date.now() > storedData.expiresAt) {
      otpStorage.delete(normalizedEmail);
      return res.status(400).json({ success: false, message: "OTP expired" });
    }

    // ✅ Compare OTP
    if (String(storedData.otp) !== String(otp)) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    // OTP is valid → mark as verified
    otpStorage.set(normalizedEmail, { ...storedData, verified: true });

    return res.status(200).json({ success: true, message: "OTP verified successfully" });

  } catch (error) {
    console.error("❌ OTP Verification Error:", error);
    return res.status(500).json({ success: false, message: "Failed to verify OTP" });
  }
};


/** Step 3: Set New Password */
export const setNewPassword = async (req, res) => {
  try {
    let { email, newPassword, confirmPassword } = req.body;

    if (!email || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: "Email, new password, and confirm password are required" });
    }

    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: "Passwords do not match" });
    }

    const normalizedEmail = email.toLowerCase();
    const storedData = otpStorage.get(normalizedEmail);

    // ✅ Check OTP verified before allowing reset
    if (!storedData || !storedData.verified) {
      return res.status(400).json({ success: false, message: "OTP verification required before resetting password" });
    }

    const user = await User.findOne({ email: normalizedEmail });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // ✅ Hash new password
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(newPassword, salt);

    // ✅ Update password
    user.password = hash;
    await user.save();

    // Clear OTP after success
    otpStorage.delete(normalizedEmail);

    return res.status(200).json({ success: true, message: "Password reset successful" });

  } catch (error) {
    console.error("❌ Password Reset Error:", error);
    return res.status(500).json({ success: false, message: "Failed to reset password" });
  }
};
