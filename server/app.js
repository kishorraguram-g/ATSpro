// app.js
const express = require('express');
const cors = require('cors');
const app = express();

// Import routers
const EmployeeRouter = require('./routes/EmployeeRoutes');
const authMiddleware = require('./middlewares/authMiddleware');
const attendenceRouter = require('./routes/AttendenceRoutes');
const departmentRouter = require('./routes/departmentRoutes');
const UserController = require('./controllers/UserController');
const checkRole=require('./middlewares/checkRole')
// Middleware
app.use(express.json());
app.use(cors());
app.use(cors({
  origin: 'http://localhost:5173', // Your frontend URL
  credentials: true
}));
// Route for user-related tasks (Employee routes like signup/login/profile)
app.use("/employees", EmployeeRouter);

// // Attendance route for employees - employeeProtect middleware ensures only employees can access
app.use("/attendance", authMiddleware.employeeProtect, attendenceRouter);


app.get('/employees',authMiddleware.employeeProtect, checkRole(['HR','Admin']), UserController.getAllUsers);

// // Default route
app.get('/', (req, res) => {
    res.send('Welcome to the Employee Attendance System!');
});



// // Department/Staff routes - accessible by staff members
app.use("/department", authMiddleware.staffProtect, departmentRouter);
