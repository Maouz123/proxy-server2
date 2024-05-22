import fetch from 'node-fetch';
import express from 'express';
import cors from 'cors';
import Tesseract from 'tesseract.js';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import os from 'os';

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_secret_key'; // Replace with a secure key

app.use(cors());
app.use(express.json());

// Middleware to log request details
app.use((req, res, next) => {
  const logEntry = {
    date: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
  };
  req.logEntry = logEntry; // Store log entry in request object for later use
  next();
});

// Middleware to validate JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    req.logEntry.accessGranted = false;
    logRequest(req.logEntry);
    return res.status(401).json({ error: 'Token missing' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      req.logEntry.accessGranted = false;
      logRequest(req.logEntry);
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = user;
    req.logEntry.accessGranted = true;
    next();
  });
};

// Function to log request details to a file on Desktop
const logRequest = (logEntry) => {
  const desktopPath = path.join(os.homedir(), 'Desktop');
  const logFilePath = path.join(desktopPath, 'requests.log');
  fs.appendFile(logFilePath, JSON.stringify(logEntry) + '\n', (err) => {
    if (err) {
      console.error('Failed to write log entry:', err);
    }
  });
};

// Endpoint to generate a JWT token
app.get('/generate-token', (req, res) => {
  const user = { name: 'user' }; // Replace with your user data
  const token = jwt.sign(user, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Endpoint to fetch image and extract text, with JWT authentication
app.get('/image', authenticateToken, async (req, res) => {
  const imageUrl = req.query.url;

  if (!imageUrl) {
    req.logEntry.accessGranted = false;
    logRequest(req.logEntry);
    return res.status(400).json({ error: 'Missing image URL' });
  }

  try {
    const response = await fetch(imageUrl);
    const imageBuffer = await response.buffer();

    const { data: { text } } = await Tesseract.recognize(imageBuffer, 'eng', {
      logger: m => console.log(m)
    });

    req.logEntry.accessGranted = true;
    logRequest(req.logEntry);

    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    });

    res.end(JSON.stringify({ imageUrl, text }));
  } catch (error) {
    req.logEntry.accessGranted = false;
    logRequest(req.logEntry);
    res.status(500).json({ error: 'Failed to fetch image or extract text' });
  }
});

// Endpoint to check log file contents
app.get('/logs', (req, res) => {
  const desktopPath = path.join(os.homedir(), 'Desktop');
  const logFilePath = path.join(desktopPath, 'requests.log');
  
  fs.readFile(logFilePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to read log file' });
    }
    res.json({ logs: data.split('\n').filter(line => line.length > 0).map(line => JSON.parse(line)) });
  });
});

app.listen(PORT, () => {
  console.log(`Proxy server is running on http://localhost:${PORT}`);
});
