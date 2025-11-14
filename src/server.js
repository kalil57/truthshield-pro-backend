const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

// Database Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/truthshield-pro')
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error(' MongoDB Error:', err));

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'success', 
    message: 'TruthShield Pro API is running!' 
  });
});

// Simple test route
app.get('/api/test', (req, res) => {
  res.json({ message: 'API is working!' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(` Server running on port ${PORT}`);
});
