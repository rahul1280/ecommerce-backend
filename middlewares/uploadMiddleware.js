const multer = require('multer');

const MB = 1024 * 1024;
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp'];

const createError = (message, statusCode) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

// Files are kept in memory only (never written to the server disk) and then sent to Cloudinary.
const createUploader = (maxSizeMb) =>
  multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: maxSizeMb * MB, files: 1 },
    fileFilter: (req, file, cb) => {
      // First, cheap check on the type the browser reported. The real check is below.
      if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
        return cb(createError('Only JPG, PNG or WebP images are allowed', 400));
      }
      cb(null, true);
    },
  });

// Look at the first bytes of the file to find out what it really is.
// The file name and the Content-Type header can be faked, the file signature cannot.
const detectImageType = (buffer) => {
  if (!buffer || buffer.length < 12) return null;

  // JPEG: FF D8 FF
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'image/jpeg';

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  const pngSignature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (pngSignature.every((byte, index) => buffer[index] === byte)) return 'image/png';

  // WebP: "RIFF" .... "WEBP"
  if (buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';

  return null;
};

// Runs after multer. Does nothing when no file was sent.
const verifyImageContent = (req, res, next) => {
  if (!req.file) return next();

  const realType = detectImageType(req.file.buffer);

  if (!realType) {
    return next(createError('The uploaded file is not a valid JPG, PNG or WebP image', 400));
  }

  req.file.mimetype = realType;
  next();
};

// Wraps multer so that its errors become clear 400 responses instead of 500s
const handleUpload = (fieldName, maxSizeMb) => {
  const upload = createUploader(maxSizeMb).single(fieldName);

  return (req, res, next) => {
    upload(req, res, (error) => {
      if (!error) return next();

      if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
          return next(createError(`Image is too large. The maximum size is ${maxSizeMb} MB`, 400));
        }
        if (error.code === 'LIMIT_UNEXPECTED_FILE') {
          return next(createError(`Unexpected file. Send the image in the "${fieldName}" field`, 400));
        }
        return next(createError(error.message, 400));
      }

      next(error);
    });
  };
};

// Profile picture: field "image", up to 2 MB
const uploadProfileImage = [handleUpload('image', 2), verifyImageContent];

// Product image: field "image", up to 5 MB. Works for multipart forms and plain JSON requests.
const uploadProductImage = [handleUpload('image', 5), verifyImageContent];

// Only admins may attach product images (moderators can still edit the text fields)
const adminOnlyImage = (req, res, next) => {
  if (req.file && req.user.role !== 'admin') {
    return next(createError('Only admins can upload product images', 403));
  }
  next();
};

// A multipart form sends every value as text. Turn price and stock back into numbers
// so the normal product validation can run unchanged.
const parseProductFormFields = (req, res, next) => {
  if (!req.is('multipart/form-data')) return next();

  ['price', 'stock'].forEach((field) => {
    const value = req.body[field];
    if (typeof value === 'string' && value.trim() !== '' && !Number.isNaN(Number(value))) {
      req.body[field] = Number(value);
    }
  });

  next();
};

module.exports = {
  uploadProfileImage,
  uploadProductImage,
  adminOnlyImage,
  parseProductFormFields,
  detectImageType,
};
