// routes/UserRoutes.js
const express = require('express');
const authController = require('../controllers/authController');
const userController = require('../controllers/UserController'); // Ensure this is the correct path to your controller

const router = express.Router();

// User signup (for staff members like supervisors or managers)
router.post('/create', authController.staffProtect, authController.signup);

// User login (for both staff and employees)
router.post('/login', authController.login);

// Get the current user's profile (protected route for staff and employees)
router.get('/me', authController.protect, authController.getMe);

// Update password (protected route, only the user can update their password)
router.post('/updatepassword', authController.protect, authController.updatePassword);


router.patch('/employees/:id', authController.protect, authController.updateUser);
router.delete('/employees/:id', authController.protect, userController.deleteUser);


module.exports = router;
