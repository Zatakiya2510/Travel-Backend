import express from "express";
import { notifyAdminOfVisitor } from "../contollers/newsletterController.js";

const router = express.Router();

router.post("/subscribe", notifyAdminOfVisitor);

export default router;
