import Booking from '../models/Booking.js';
import User from '../models/User.js';

export const createBooking = async (req, res) => {
    const newBooking = new Booking(req.body);

    try {
        const savedBooking = await newBooking.save();
        res.status(200).json({
            success: true,
            message: 'Your tour is booked',
            data: savedBooking
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

export const getBooking = async (req, res) => {
    const id = req.params.id;
    try {
        const book = await Booking.findById(id);
        if (!book) {
            return res.status(404).json({
                success: false,
                message: 'Booking not found'
            });
        }
        res.status(200).json({
            success: true,
            message: 'Booking found',
            data: book
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

export const getAllBooking = async (req, res) => {
    try {
        const books = await Booking.find();
        res.status(200).json({
            success: true,
            message: 'All bookings fetched successfully',
            data: books
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};

export const getBookingByUserId = async (req, res) => {
    const userId = req.params.userId; // Retrieve user ID from parameters
    try {
        const books = await Booking.find({ userId: userId }); // Find bookings by user ID
        res.status(200).json({
            success: true,
            message: 'Bookings fetched by user ID',
            data: books
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};


