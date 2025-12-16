const validator = require('validator');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);

// Фільтр XSS для вихідних даних
const xssFilterOutput = (req, res, next) => {
  const originalJson = res.json;

  res.json = function (data) {
    if (data && typeof data === 'object') {
      // Рекурсивна санація всіх рядків у відповіді
      const sanitizeData = (obj) => {
        if (obj === null || obj === undefined) return obj;

        if (typeof obj === 'string') {
          // Очищення HTML через DOMPurify
          return DOMPurify.sanitize(obj, {
            ALLOWED_TAGS: [],
            ALLOWED_ATTR: []
          });
        }

        if (Array.isArray(obj)) {
          return obj.map(item => sanitizeData(item));
        }

        if (typeof obj === 'object') {
          const sanitized = {};
          for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
              sanitized[key] = sanitizeData(obj[key]);
            }
          }
          return sanitized;
        }

        return obj;
      };

      data = sanitizeData(data);
    }

    return originalJson.call(this, data);
  };

  next();
};

// Middleware для перевірки Content-Type
const validateContentType = (req, res, next) => {
  const allowedContentTypes = [
    'application/json',
    'application/x-www-form-urlencoded'
  ];

  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.headers['content-type'];

    if (
      !contentType ||
      !allowedContentTypes.some(type => contentType.includes(type))
    ) {
      return res.status(415).json({
        success: false,
        message: 'Непідтримуваний тип контенту'
      });
    }
  }

  next();
};

module.exports = {
  xssFilterOutput,
  validateContentType
};
