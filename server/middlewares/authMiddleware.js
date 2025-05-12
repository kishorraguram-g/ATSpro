const authController = require('../controllers/authController');
const jwt = require('jsonwebtoken');
exports.employeeProtect = (req, res, next) => {
    console.log('Hello from Employee Middleware');
    authController.protect(req, res, next);
};

exports.staffProtect = (req, res, next) => {
    console.log('Hello from Staff Middleware');
    authController.staffProtect(req, res, next);
};

// authMiddleware.js
exports.authenticateUser = (req, res, next) => {
    // Verify the JWT token and attach the user to the request
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
    if (!token) {
        return res.status(401).json({ status: 'fail', message: 'Authorization token missing' });
    }
    
    // Assuming you have a function to verify JWT (e.g., using jsonwebtoken)
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ status: 'fail', message: 'Invalid token' });
        }
        req.user = decoded;  // Attach user to the request
        next();
    });
};
