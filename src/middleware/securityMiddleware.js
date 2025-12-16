const helmet = require('helmet');

// Розширені налаштування Helmet
const securityHeaders = (req, res, next) => {
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "font-src 'self'; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "form-action 'self';"
  );

  // X-XSS-Protection (застаріле, але для сумісності)
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // X-Content-Type-Options
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // X-Frame-Options
  res.setHeader('X-Frame-Options', 'DENY');

  // Referrer-Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions-Policy
  res.setHeader(
    'Permissions-Policy',
    'geolocation=(), microphone=(), camera=()'
  );

  next();
};

// Захист від Clickjacking
const preventClickjacking = (req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
};

// Захист від MIME sniffing
const preventMIMESniffing = (req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
};

// Захист від XSS через заголовки
const xssProtection = (req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
};

module.exports = {
  securityHeaders,
  preventClickjacking,
  preventMIMESniffing,
  xssProtection
};
