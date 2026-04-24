require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const authRoutes = require('./routes/auth');

const app = express();
const PORT = process.env.PORT || 3001;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://mongo:27017/authdb';

// Middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', service: 'auth-service', timestamp: new Date().toISOString() });
});

// Routes
app.use('/api/auth', authRoutes);

// Global error handler
app.use((err, req, res, next) => {
  console.error(`[AUTH-SERVICE ERROR] ${err.stack}`);
  res.status(err.status || 500).json({
    error: err.message || 'Internal Server Error',
    service: 'auth-service'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found', service: 'auth-service' });
});

// Connect to MongoDB and start server
const connectWithRetry = async () => {
  const maxRetries = 10;
  let retries = 0;
  while (retries < maxRetries) {
    try {
      await mongoose.connect(MONGO_URI);
      console.log(`[AUTH-SERVICE] Connected to MongoDB at ${MONGO_URI}`);
      app.listen(PORT, () => {
        console.log(`[AUTH-SERVICE] Running on port ${PORT}`);
      });
      return;
    } catch (err) {
      retries++;
      console.error(`[AUTH-SERVICE] MongoDB connection failed (attempt ${retries}/${maxRetries}): ${err.message}`);
      if (retries < maxRetries) {
        console.log(`[AUTH-SERVICE] Retrying in 5 seconds...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  }
  console.error('[AUTH-SERVICE] Failed to connect to MongoDB after maximum retries. Exiting.');
  process.exit(1);
};

connectWithRetry();
