// Import libraries
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// Initialize the app
const app = express();
const port = 3000;

// Middleware for security headers (using Helmet)
app.use(helmet());

// Middleware for rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per window
  message: "Too many requests from this IP, please try again after 15 minutes."
});
app.use(limiter);

// Custom WAF Middleware
app.use((req, res, next) => {
  // Check for suspicious patterns in query strings or body
  const suspiciousPatterns = [/(\%27)|(\')|(\-\-)|(\%23)|(#)/i, /<script.*?>.*?<\/script>/i, /(\bselect\b|\bunion\b|\bdelete\b|\bdrop\b)/i];

  const checkPatterns = (input) => suspiciousPatterns.some((pattern) => pattern.test(input));

  // Check query strings
  if (req.query && Object.values(req.query).some(checkPatterns)) {
    return res.status(403).send("Forbidden: Suspicious query detected.");
  }

  // Check body (if content type is JSON)
  if (req.body && typeof req.body === 'object') {
    if (Object.values(req.body).some(checkPatterns)) {
      return res.status(403).send("Forbidden: Suspicious payload detected.");
    }
  }

  next();
});

// Test Route
app.get('/', (req, res) => {
  res.send('WAF is active. Your request is safe.');
});

// Route for testing SQL injection protection
app.get('/test', (req, res) => {
  res.send('This route is protected from SQL Injection.');
});

// Start the server
app.listen(port, () => {
  console.log(`WAF app listening at http://localhost:${port}`);
});
