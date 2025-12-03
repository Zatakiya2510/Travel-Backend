import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

// ✅ Gmail SMTP transporter (works locally; Render may block ports)
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587, // use 587 (TLS)
  secure: false,
  auth: {
    user: process.env.EMAIL_USER, // travelworld official email
    pass: process.env.EMAIL_PASS, // Gmail app password
  },
  tls: { rejectUnauthorized: false },
});

export const notifyAdminOfVisitor = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: "Valid email is required." });
    }

    const time = new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" });

    // ✅ Prepare email for admin inbox
    const mailOptions = {
      from: process.env.EMAIL_USER, // Always use your verified sender email
      to: process.env.EMAIL_USER,   // Send to admin inbox
      replyTo: email,               // This allows admin to reply directly to the visitor
      subject: `🌍 New Visitor on Travel World Website`,
      html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h2>🚀 New Visitor Notification</h2>
          <p>A new user has visited your website!</p>
          <p><strong>Visitor Email:</strong> ${email}</p>
          <p><strong>Visited On:</strong> ${time}</p>
          <hr/>
          <p style="font-size:13px;color:#777;">This is an automated message from your Travel World website.</p>
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Notification email sent for ${email}`);

    return res.status(200).json({
      success: true,
      message: "Thank you for visiting! The admin has been notified.",
    });
  } catch (error) {
    console.error("❌ Error sending notification:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to send notification. Try again later.",
    });
  }
};
