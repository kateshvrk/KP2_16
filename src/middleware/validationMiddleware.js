const { body, param, query, validationResult } = require('express-validator');
const validator = require('validator');

const validateRequest = (validations) => {
  return async (req, res, next) => {
    // Запускаємо всі валідації
    await Promise.all(validations.map(validation => validation.run(req)));

    const errors = validationResult(req);
    if (errors.isEmpty()) {
      return next();
    }

    const extractedErrors = errors.array().map(err => ({
      field: err.param,
      message: err.msg,
      location: err.location
    }));

    return res.status(400).json({
      success: false,
      message: 'Помилка валідації',
      errors: extractedErrors
    });
  };
};

module.exports = {
  body,
  param,
  query,
  validator,
  validateRequest
};
// Валідація для реєстрації користувача
const registerValidation = [
  body('username')
    .trim()
    .escape() // Екранування HTML спецсимволів
    .notEmpty().withMessage("Ім'я користувача обов'язкове")
    .isLength({ min: 3, max: 30 }).withMessage("Ім'я має бути від 3 до 30 символів")
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Допустимі лише літери, цифри та підкреслення'),

  body('email')
    .trim()
    .normalizeEmail() // Нормалізація email
    .isEmail().withMessage('Введіть коректний email')
    .customSanitizer(email => email.toLowerCase()),

  body('password')
    .isLength({ min: 8 }).withMessage('Пароль має містити мінімум 8 символів')
    .matches(/[A-Z]/).withMessage('Пароль має містити хоча б одну велику літеру')
    .matches(/[a-z]/).withMessage('Пароль має містити хоча б одну малу літеру')
    .matches(/[0-9]/).withMessage('Пароль має містити хоча б одну цифру')
    .matches(/[!@#$%^&*(),.?":{}|<>]/).withMessage('Пароль має містити хоча б один спецсимвол')
];

module.exports = registerValidation;
// Валідація для продуктів
const productValidation = [
  body('name')
    .trim()
    .escape()
    .notEmpty().withMessage("Назва продукту обов'язкова")
    .isLength({ max: 100 }).withMessage('Назва не повинна перевищувати 100 символів'),

  body('description')
    .trim()
    .escape() // Захист від XSS
    .notEmpty().withMessage("Опис продукту обов'язковий")
    .isLength({ max: 500 }).withMessage('Опис не повинен перевищувати 500 символів'),

  body('price')
    .isFloat({ min: 0 }).withMessage('Ціна має бути позитивним числом')
    .toFloat(),

  body('category')
    .isIn(['electronics', 'clothing', 'books', 'food', 'other'])
    .withMessage('Невірна категорія'),

  body('quantity')
    .optional()
    .isInt({ min: 0 }).withMessage("Кількість не може бути від'ємною")
    .toInt()
];

module.exports = productValidation;
// Sanitization middleware для всіх запитів
const sanitizeInput = (req, res, next) => {
  // Функція для рекурсивної санації об'єкта
  const sanitizeObject = (obj) => {
    if (!obj || typeof obj !== 'object') return obj;

    for (const key in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        if (typeof obj[key] === 'string') {
          // Екранування HTML спецсимволів
          obj[key] = validator.escape(obj[key]);

          // Видалення потенційно небезпечних script-тегів
          obj[key] = obj[key].replace(
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            ''
          );
        } else if (typeof obj[key] === 'object') {
          sanitizeObject(obj[key]);
        }
      }
    }

    return obj;
  };

  // Санація body, query та params
  if (req.body) sanitizeObject(req.body);
  if (req.query) sanitizeObject(req.query);
  if (req.params) sanitizeObject(req.params);

  next();
};

module.exports = sanitizeInput;
// Захист від NoSQL ін'єкцій
const preventNoSQLInjection = (req, res, next) => {
  const checkForInjection = (obj) => {
    if (!obj || typeof obj !== 'object') return;

    for (const key in obj) {
      const value = obj[key];

      if (typeof value === 'string') {
        // Блокуємо MongoDB оператори
        const mongoOperators = [
          '$where', '$ne', '$gt', '$gte', '$lt', '$lte', '$in', '$nin',
          '$and', '$or', '$not', '$nor', '$exists', '$type', '$mod', '$regex',
          '$text', '$expr', '$jsonSchema', '$all', '$elemMatch', '$size'
        ];

        for (const op of mongoOperators) {
          if (value.includes(op)) {
            return res.status(400).json({
              success: false,
              message: 'Потенційно небезпечний запит'
            });
          }
        }

        // Видалення потенційно небезпечних символів
        if (/[\$\[\]\{\}]/.test(value)) {
          obj[key] = value.replace(/[\$\[\]\{\}]/g, '');
        }
      } else if (typeof value === 'object') {
        checkForInjection(value);
      }
    }
  };

  checkForInjection(req.body);
  checkForInjection(req.query);

  next();
};

module.exports = preventNoSQLInjection;
module.exports = {
  validateRequest,
  registerValidation,
  productValidation,
  sanitizeInput,
  preventNoSQLInjection
};
