import express from 'express';
import { verifyAdmin, verifyUser } from '../utils/verifyToken.js';
import { createBooking, getBooking, getAllBooking, getBookingByUserId } from '../contollers/bookingController.js';

const router = express.Router();

// Create a booking
router.post('/', createBooking);

// Get a specific booking by ID
router.get('/:id', getBooking);

// Get all bookings (requires admin privileges)
router.get('/',  getAllBooking);

// Get bookings by user email
router.get('/user/:userId', getBookingByUserId);

export default router;
