// server.js - Main Express server
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Create uploads directory if it doesn't exist
const fs = require('fs');
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/pawpass', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  firstName: { type: String, trim: true },
  lastName: { type: String, trim: true },
  phone: { type: String, trim: true },
  address: {
    street: String,
    city: String,
    province: String,
    postalCode: String,
    country: { type: String, default: 'Thailand' }
  },
  emergencyContact: {
    name: String,
    phone: String,
    relation: String
  },
  subscription: {
    tier: { type: String, enum: ['free', 'silver', 'gold', 'platinum'], default: 'free' },
    expiresAt: Date,
    isActive: { type: Boolean, default: true }
  },
  pawPoints: { type: Number, default: 0 },
  level: { type: Number, default: 1 },
  badges: [String],
  preferences: {
    language: { type: String, default: 'en' },
    notifications: {
      email: { type: Boolean, default: true },
      push: { type: Boolean, default: true },
      sms: { type: Boolean, default: false }
    },
    privacy: {
      profileVisibility: { type: String, enum: ['public', 'friends', 'private'], default: 'public' },
      locationSharing: { type: Boolean, default: false }
    }
  },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
  lastActive: { type: Date, default: Date.now }
});

// Pet Schema
const petSchema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true, trim: true },
  species: { type: String, required: true }, // dog, cat, bird, etc.
  breed: { type: String, trim: true },
  gender: { type: String, enum: ['male', 'female', 'unknown'] },
  birthDate: Date,
  weight: { type: Number }, // in kg
  color: { type: String, trim: true },
  markings: { type: String, trim: true },
  
  // Medical Information
  microchipId: { type: String, trim: true },
  vaccinations: [{
    name: String,
    dateGiven: Date,
    nextDue: Date,
    veterinarian: String,
    notes: String
  }],
  medications: [{
    name: String,
    dosage: String,
    frequency: String,
    startDate: Date,
    endDate: Date,
    prescribedBy: String,
    notes: String
  }],
  allergies: [String],
  medicalNotes: String,
  preferredVet: {
    name: String,
    phone: String,
    address: String
  },
  
  // Care Tracking
  feeding: {
    brand: String,
    amount: String,
    frequency: String,
    lastFed: Date
  },
  exercise: {
    dailyGoal: Number, // minutes
    lastWalk: Date,
    averageDaily: Number
  },
  grooming: {
    lastGroomed: Date,
    frequency: String, // weekly, monthly, etc.
    groomer: String
  },
  
  // Lost Pet Information
  isLost: { type: Boolean, default: false },
  lostDetails: {
    dateLost: Date,
    location: {
      lat: Number,
      lng: Number,
      address: String
    },
    description: String,
    reward: Number,
    contactInfo: String,
    foundDate: Date,
    foundBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  
  // QR Code and ICE Card
  qrCode: String, // Generated QR code ID
  iceCardEnabled: { type: Boolean, default: false },
  iceCardData: {
    emergencyContacts: [{
      name: String,
      phone: String,
      relation: String
    }],
    medicalAlerts: [String],
    visibility: { type: String, enum: ['minimal', 'standard', 'full'], default: 'standard' }
  },
  
  // Photos and Media
  profilePhoto: String,
  photos: [String], // Array of photo URLs
  
  // Social Features (for future stages)
  followers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  likes: { type: Number, default: 0 },
  fanClubEnabled: { type: Boolean, default: false },
  
  // Virtual Pet (gamification)
  virtualPet: {
    level: { type: Number, default: 1 },
    xp: { type: Number, default: 0 },
    happiness: { type: Number, default: 100 },
    health: { type: Number, default: 100 },
    accessories: [String],
    lastPlayed: Date
  },
  
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Activity Log Schema (for tracking and analytics)
const activitySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pet: { type: mongoose.Schema.Types.ObjectId, ref: 'Pet' },
  type: { 
    type: String, 
    required: true,
    enum: ['feeding', 'walking', 'grooming', 'vet_visit', 'medication', 'vaccination', 'play', 'training', 'photo_upload', 'lost_report', 'found_report']
  },
  description: String,
  data: mongoose.Schema.Types.Mixed, // Flexible data storage
  pawPointsEarned: { type: Number, default: 0 },
  location: {
    lat: Number,
    lng: Number,
    address: String
  },
  createdAt: { type: Date, default: Date.now }
});

// Service Provider Schema (for Stage 4 marketplace)
const serviceProviderSchema = new mongoose.Schema({
  name: { type: String, required: true },
  type: { type: String, enum: ['vet', 'groomer', 'boarding', 'walker', 'trainer'], required: true },
  email: String,
  phone: String,
  address: {
    street: String,
    city: String,
    province: String,
    postalCode: String,
    coordinates: {
      lat: Number,
      lng: Number
    }
  },
  services: [{
    name: String,
    description: String,
    price: Number,
    duration: Number, // in minutes
    available: { type: Boolean, default: true }
  }],
  hours: {
    monday: { open: String, close: String },
    tuesday: { open: String, close: String },
    wednesday: { open: String, close: String },
    thursday: { open: String, close: String },
    friday: { open: String, close: String },
    saturday: { open: String, close: String },
    sunday: { open: String, close: String }
  },
  rating: { type: Number, default: 0 },
  reviewCount: { type: Number, default: 0 },
  isVerified: { type: Boolean, default: false },
  isPartner: { type: Boolean, default: false },
  photos: [String],
  createdAt: { type: Date, default: Date.now }
});

// Create models
const User = mongoose.model('User', userSchema);
const Pet = mongoose.model('Pet', petSchema);
const Activity = mongoose.model('Activity', activitySchema);
const ServiceProvider = mongoose.model('ServiceProvider', serviceProviderSchema);

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// JWT middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.userId = user.userId;
    next();
  });
};

// Helper function to generate QR code ID
const generateQRId = () => {
  return 'PW' + Date.now().toString(36).toUpperCase() + Math.random().toString(36).substr(2, 4).toUpperCase();
};

// Routes

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, firstName, lastName, phone } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }]
    });

    if (existingUser) {
      return res.status(409).json({ error: 'User with this email or username already exists' });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const user = new User({
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      password: hashedPassword,
      firstName,
      lastName,
      phone
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        subscription: user.subscription,
        pawPoints: user.pawPoints,
        level: user.level
      },
      token
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { login, password } = req.body; // login can be username or email

    if (!login || !password) {
      return res.status(400).json({ error: 'Username/email and password are required' });
    }

    // Find user by username or email
    const user = await User.findOne({
      $or: [
        { email: login.toLowerCase() },
        { username: login.toLowerCase() }
      ]
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Update last active
    user.lastActive = new Date();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        subscription: user.subscription,
        pawPoints: user.pawPoints,
        level: user.level,
        badges: user.badges
      },
      token
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ user });
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const allowedUpdates = ['firstName', 'lastName', 'phone', 'address', 'emergencyContact', 'preferences'];
    const updates = {};
    
    for (const field of allowedUpdates) {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    }
    
    updates.updatedAt = new Date();

    const user = await User.findByIdAndUpdate(
      req.userId, 
      { $set: updates }, 
      { new: true, runValidators: true }
    ).select('-password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Profile update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create pet profile
app.post('/api/pets', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const petData = {
      ...req.body,
      owner: req.userId,
      qrCode: generateQRId()
    };

    // Handle photo upload
    if (req.file) {
      petData.profilePhoto = `/uploads/${req.file.filename}`;
      petData.photos = [petData.profilePhoto];
    }

    // Parse dates if provided
    if (petData.birthDate) {
      petData.birthDate = new Date(petData.birthDate);
    }

    const pet = new Pet(petData);
    await pet.save();

    // Award points for creating pet profile
    await User.findByIdAndUpdate(req.userId, { 
      $inc: { pawPoints: 50 },
      $addToSet: { badges: 'first_pet' }
    });

    // Log activity
    const activity = new Activity({
      user: req.userId,
      pet: pet._id,
      type: 'photo_upload',
      description: `Created profile for ${pet.name}`,
      pawPointsEarned: 50
    });
    await activity.save();

    res.status(201).json({
      message: 'Pet profile created successfully',
      pet,
      pawPointsEarned: 50
    });

  } catch (error) {
    console.error('Pet creation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user's pets
app.get('/api/pets', authenticateToken, async (req, res) => {
  try {
    const pets = await Pet.find({ owner: req.userId }).sort({ createdAt: -1 });
    res.json({ pets });
  } catch (error) {
    console.error('Pets fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get specific pet
app.get('/api/pets/:petId', authenticateToken, async (req, res) => {
  try {
    const pet = await Pet.findOne({ 
      _id: req.params.petId, 
      owner: req.userId 
    });

    if (!pet) {
      return res.status(404).json({ error: 'Pet not found' });
    }

    res.json({ pet });
  } catch (error) {
    console.error('Pet fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update pet profile
app.put('/api/pets/:petId', authenticateToken, upload.single('photo'), async (req, res) => {
  try {
    const updates = { ...req.body, updatedAt: new Date() };

    // Handle photo upload
    if (req.file) {
      updates.profilePhoto = `/uploads/${req.file.filename}`;
      if (!updates.photos) {
        updates.$push = { photos: updates.profilePhoto };
      }
    }

    const pet = await Pet.findOneAndUpdate(
      { _id: req.params.petId, owner: req.userId },
      { $set: updates },
      { new: true, runValidators: true }
    );

    if (!pet) {
      return res.status(404).json({ error: 'Pet not found' });
    }

    res.json({ message: 'Pet profile updated successfully', pet });
  } catch (error) {
    console.error('Pet update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add activity log
app.post('/api/activities', authenticateToken, async (req, res) => {
  try {
    const { petId, type, description, data } = req.body;

    // Verify pet belongs to user
    const pet = await Pet.findOne({ _id: petId, owner: req.userId });
    if (!pet) {
      return res.status(404).json({ error: 'Pet not found' });
    }

    // Calculate points based on activity type
    const pointValues = {
      feeding: 5,
      walking: 10,
      grooming: 15,
      vet_visit: 25,
      medication: 5,
      vaccination: 20,
      play: 5,
      training: 10,
      photo_upload: 5
    };

    const pointsEarned = pointValues[type] || 0;

    const activity = new Activity({
      user: req.userId,
      pet: petId,
      type,
      description,
      data,
      pawPointsEarned: pointsEarned
    });

    await activity.save();

    // Update user points and pet virtual pet stats
    await User.findByIdAndUpdate(req.userId, { 
      $inc: { pawPoints: pointsEarned } 
    });

    if (type === 'feeding' || type === 'walking' || type === 'play') {
      await Pet.findByIdAndUpdate(petId, {
        $inc: { 
          'virtualPet.xp': pointsEarned,
          'virtualPet.happiness': Math.min(5, pointsEarned)
        },
        'virtualPet.lastPlayed': new Date()
      });
    }

    res.status(201).json({
      message: 'Activity logged successfully',
      activity,
      pawPointsEarned: pointsEarned
    });

  } catch (error) {
    console.error('Activity log error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get activities for a pet
app.get('/api/pets/:petId/activities', authenticateToken, async (req, res) => {
  try {
    const pet = await Pet.findOne({ _id: req.params.petId, owner: req.userId });
    if (!pet) {
      return res.status(404).json({ error: 'Pet not found' });
    }

    const activities = await Activity.find({ 
      user: req.userId, 
      pet: req.params.petId 
    }).sort({ createdAt: -1 }).limit(50);

    res.json({ activities });
  } catch (error) {
    console.error('Activities fetch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Generate/Update ICE Card
app.post('/api/pets/:petId/ice-card', authenticateToken, async (req, res) => {
  try {
    const { emergencyContacts, medicalAlerts, visibility } = req.body;

    const pet = await Pet.findOneAndUpdate(
      { _id: req.params.petId, owner: req.userId },
      {
        $set: {
          iceCardEnabled: true,
          'iceCardData.emergencyContacts': emergencyContacts,
          'iceCardData.medicalAlerts': medicalAlerts,
          'iceCardData.visibility': visibility || 'standard',
          updatedAt: new Date()
        }
      },
      { new: true }
    );

    if (!pet) {
      return res.status(404).json({ error: 'Pet not found' });
    }

    res.json({ message: 'ICE card updated successfully', iceCardData: pet.iceCardData });
  } catch (error) {
    console.error('ICE card error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Public ICE card access (for QR code scanning)
app.get('/api/ice/:qrCode', async (req, res) => {
  try {
    const pet = await Pet.findOne({ 
      qrCode: req.params.qrCode,
      iceCardEnabled: true 
    }).populate('owner', 'firstName lastName phone emergencyContact');

    if (!pet) {
      return res.status(404).json({ error: 'ICE card not found' });
    }

    // Return data based on visibility setting
    const { visibility } = pet.iceCardData;
    const response = {
      petName: pet.name,
      species: pet.species,
      breed: pet.breed
    };

    if (visibility === 'standard' || visibility === 'full') {
      response.emergencyContacts = pet.iceCardData.emergencyContacts;
      response.medicalAlerts = pet.iceCardData.medicalAlerts;
      response.ownerName = `${pet.owner.firstName} ${pet.owner.lastName}`.trim();
    }

    if (visibility === 'full') {
      response.ownerPhone = pet.owner.phone;
      response.preferredVet = pet.preferredVet;
    }

    res.json(response);
  } catch (error) {
    console.error('ICE card access error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Report lost pet
app.post('/api/pets/:petId/report-lost', authenticateToken, async (req, res) => {
  try {
    const { location, description, reward, contactInfo } = req.body;

    const pet = await Pet.findOneAndUpdate(
      { _id: req.params.petId, owner: req.userId },
      {
        $set: {
          isLost: true,
          'lostDetails.dateLost': new Date(),
          'lostDetails.location': location,
          'lostDetails.description': description,
          'lostDetails.reward': reward,
          'lostDetails.contactInfo': contactInfo,
          updatedAt: new Date()
        }
      },
      { new: true }
    );

    if (!pet) {
      return res.status(404).json({ error: 'Pet not found' });
    }

    // TODO: Implement geo-based notifications to nearby users

    res.json({ message: 'Lost pet report submitted successfully', pet });
  } catch (error) {
    console.error('Lost pet report error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large' });
    }
  }
  res.status(500).json({ error: error.message });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`PawPass backend server running on port ${PORT}`);
  console.log(`MongoDB connected to ${process.env.MONGODB_URI || 'mongodb://localhost:27017/pawpass'}`);
});

module.exports = { app, User, Pet, Activity, ServiceProvider };