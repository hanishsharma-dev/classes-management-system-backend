import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

// Load environment variables from a .env file
dotenv.config();

const app = express();

// CORS configuration to allow requests from a specific origin
const corsOptions = {
    origin: 'http://localhost:5173',  // Frontend URL to allow cross-origin requests
};
app.use(cors(corsOptions));  // Enable CORS with the specified options
app.use(express.json());  // Middleware to parse JSON request bodies

const URI = process.env.MONGO_URI || '';  // MongoDB connection string from environment variables

// Connect to MongoDB using Mongoose
mongoose.connect(URI)
    .then(() => console.log('MongoDB connected!'))
    .catch(err => console.error('MongoDB connection error:', err));

// Define the schema and model for users
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },  // Unique email for each user
    fullName: { type: String, required: true },  // Full name of the user
    password: { type: String, required: true }, // Password (hashed) for authentication
});

const User = mongoose.model('User', userSchema);

// JWT Authentication Middleware to protect routes
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];  // Get the Authorization header
    const token = authHeader && authHeader.split(' ')[1];  // Extract the token from the header

    if (!token) {
        return res.sendStatus(401);  // Return 401 if no token is provided
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {  // Verify the token
        if (err) {
            return res.sendStatus(403);  // Return 403 if token is invalid
        }
        req.user = user;  // Attach user info to the request object
        next();  // Proceed to the next middleware/route handler
    });
};

// Register API to create a new user
app.post('/register', async (req, res) => {
    try {
        const { email, fullName, password } = req.body;

        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash the password before saving
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create and save a new user with the hashed password
        const newUser = new User({ email, fullName, password: hashedPassword });
        await newUser.save();

        // Exclude sensitive information (like the password) from the response
        res.status(201).json({
            _id: newUser._id,
            email: newUser.email,
            fullName: newUser.fullName,
        });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

// Login API to authenticate a user and generate a JWT
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });  // Unauthorized error for invalid credentials
        }

        // Compare the provided password with the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });  // Consistent error response for invalid credentials
        }

        // Generate a JWT token for the authenticated user
        const token = jwt.sign(
            { userId: user._id }, 
            process.env.JWT_SECRET, 
            { expiresIn: '8h' }  // Token expiration time
        );

        // Respond with the token and user info (excluding password)
        res.status(200).json({
            token, 
            user: { 
                id: user._id, 
                email: user.email, 
                fullName: user.fullName 
            }
        });
    } catch (err) {
        // Log the error for internal debugging and respond with a generic message
        console.error('Login Error:', err.message);
        res.status(500).json({ message: 'Server error. Please try again later.' });  // Return a generic error message for server issues
    }
});

// Route to get static suit categories and images (protected by JWT)
app.get('/classesList', authenticateToken, (req, res) => {
    try {
        const classesList = [
            { "className": "11th", "_id": "1" },
            { "className": "12th", "_id": "2" },
            { "className": "BCA", "_id": "3" },
            { "className": "MCA", "_id": "4" },
            { "className": "BSC", "_id": "5" },
            { "className": "MBA", "_id": "6" },
            { "className": "BBA", "_id": "7" }
        ];

        res.status(200).json({
            success: true,
            message: 'Classes list fetched successfully',
            data: classesList
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Failed to fetch classes list',
            error: err.message
        });
    }
});

// Start the server on a specified port
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
