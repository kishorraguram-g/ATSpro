const Employee = require('../models/EmployeeModel');
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const handleError = require('./errorController');

// Function to create JWT token
const signin = id => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

// Signup handler
exports.signup = async (req, res) => {
    try {
        const {
            name, email, password, confirmPassword,
            department, designation,joiningDate
        } = req.body;
        console.log(req.body);
        // 1. Password Match Check
        if (password !== confirmPassword) {
            console.log("Password and confirmPassword do not match");
            return res.status(400).json({
                status: "fail",
                message: "Password and confirmPassword do not match 💥"
            });
        
        }


        // 2. Get the user performing signup (from auth middleware)
        const creator = req.user; // Comes from protect middleware
        if (!creator) {
            console.log("Creator not found in request");
            return res.status(401).json({
                status: "fail",
                message: "You must be logged in to create users"
            });
        }

        // 3. Restriction Logic
        const allowedRoles = [
            'Developer', 'Lead Developer', 'Project Manager', 
            'HR', 'Admin', 'Manager', 'QA', 'Tech Support', 
            'UX/UI Designer', 'System Architect'
        ];


        if (!allowedRoles.includes(designation)) {
            
            console.log("Invalid role designation");
            return res.status(400).json({
                status: "fail",
                message: "Invalid role designation"
            });
        }

        // Restricting the role creation logic based on creator's designation
        if (["Manager", "HR"].includes(designation)) {
            if (creator.designation !== "Admin") {
                console.log("Only Admin can create Manager or HR roles");
                return res.status(403).json({
                    status: "fail",
                    message: "Only Admin can create Manager or HR roles"
                });
            }
        }
        if (designation === "Admin") {
            console.log("Admin account creation is restricted");
            return res.status(403).json({
                status: "fail",
                message: "You cannot create Admin accounts through signup"
            });
        }
        console.log("Creator designation:", creator.designation);
        if ( creator.designation != "HR" && designation === "Employee") {
            console.log("Only HR can create Employee accounts");
            return res.status(403).json({
                status: "fail",
                message: "Only HR can create Employee accounts"
            });
        }

        
        // const employeeJoiningDate = joiningDate ? new Date(joiningDate) : new Date();

        // 4. Create the user
        console.log("Creating new employee...");
        const newEmployee = await Employee.create({
            name, email, password, department, designation,joiningDate
        });

        console.log("New employee created:", newEmployee);
        const token = signin(newEmployee._id);
        newEmployee.password = undefined;

        res.status(201).json({
            status: "success",
            token,
            data: { user: newEmployee }
        });

    } catch (err) {
        console.log("Error during signup", err);
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

// Login handler
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(email," ",password)

        // 1. Check if email and password exist
        if (!email || !password) {
            return res.status(400).json({
                status: "fail",
                message: "Please provide email and password"
            });
        }

        // 2. Check if user exists and validate password
        const employee = await Employee.findOne({ email }).select('+password');
        console.log("Employee found:", employee);
        if (!employee || password !== employee.password) {  // Direct password comparison
            return res.status(401).json({
                status: "fail",
                message: "Incorrect email or password"
            });
        }

        // 3. Generate token and send response
        const token = signin(employee._id);
        res.status(200).json({
            status: "success",
            token,
            designation: employee.designation,
            employeeId: employee._id,
        });

    } catch (err) {
        console.log("Error during login", err);
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};


// Update Password handler
exports.updatePassword = async (req, res) => {
    try {
        const { email, password, updatePassword, confirmPassword } = req.body;

        // 1. Validate email
        if (!email) {
            return res.status(400).json({
                status: 'fail',
                message: 'Please provide email'
            });
        }

        // 2. Find the user and validate current password
        const employee = await Employee.findOne({ email }).select('+password');
        if (!employee || !(await employee.comparePassword(password, employee.password))) {
            return res.status(401).json({
                status: "fail",
                message: "Incorrect email or password"
            });
        }

        // 3. Password match validation
        if (updatePassword !== confirmPassword) {
            return res.status(400).json({
                status: 'fail',
                message: "Update Password and confirm password do not match"
            });
        }

        // 4. Update password
        employee.password = updatePassword;
        await employee.save();

        res.status(200).json({
            status: 'success',
            message: 'Password updated successfully',
            user: employee
        });

    } catch (err) {
        res.status(500).json({
            status: 'fail',
            message: err.message
        });
    }
};

// Protect middleware for general authentication
exports.protect = async (req, res, next) => {
    try {
        // 1) Get token and verify if it's present
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({
                status: "fail",
                message: "You are not logged in! Please log in to get access"
            });
        }

        // 2) Decode token
        const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

        // 3) Check if the user still exists
        const freshEmployee = await Employee.findById(decoded.id);
        if (!freshEmployee) {
            return res.status(404).json({
                status: "fail",
                message: "The user belonging to the token no longer exists"
            });
        }

        // 4) Check if the password was changed after token issuance
        if (freshEmployee.changePasswordAfter(decoded.iat)) {
            return res.status(401).json({
                status: "fail",
                message: "Employee recently changed password! Please log in again"
            });
        }

        // Grant access to protected route
        req.user = freshEmployee;
        // console.log('protect :',req.user);
        next();

    } catch (err) {
        console.log("Error in protection middleware", err);
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

// Staff Protection middleware (role-based)
exports.staffProtect = async (req, res, next) => {
    try {
        let token;
        if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
            token = req.headers.authorization.split(' ')[1];
        }

        if (!token) {
            return res.status(401).json({
                status: "fail",
                message: "You are not logged in! Please log in to get access"
            });
        }

        // 2) Verify token
        const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

        // 3) Check if the user still exists
        const freshEmployee = await Employee.findById(decoded.id);
        if (!freshEmployee) {
            return res.status(404).json({
                status: "fail",
                message: "The user belonging to the token no longer exists"
            });
        }

        // 4) Check if the password was changed after token issuance
        if (freshEmployee.changePasswordAfter(decoded.iat)) {
            return res.status(401).json({
                status: "fail",
                message: "Employee recently changed password! Please log in again"
            });
        }

        // 5) Check if the user has appropriate role
        const allowedRoles = [
            'Developer', 'Lead Developer', 'Project Manager', 
            'HR', 'Admin', 'Manager', 'QA', 'Tech Support', 
            'UX/UI Designer', 'System Architect'
        ];
        if (!allowedRoles.includes(freshEmployee.designation)) {
            return res.status(403).json({
                status: "fail",
                message: "You are not authorized to access this route"
            });
        }

        // Grant access
        req.user = freshEmployee;
        // console.log(req.user);
        next();

    } catch (err) {
        console.log("Error in staff protection middleware", err);
        res.status(500).json({
            status: "fail",
            message: 'Staff authentication failed'
        });
    }
};

// Get current logged-in user data
exports.getMe = async (req, res) => {
    try {
        const employee = req.user;

        res.status(200).json({
            status: 'success',
            data: { user: employee }
        });
    } catch (err) {
        res.status(500).json({
            status: 'fail',
            message: err.message
        });
    }
};


// Update User handler
exports.updateUser = async (req, res) => {
    try {
        const { id } = req.params;
        const { name, email, department, designation, joiningDate } = req.body;
        const updater = req.user;

        console.log('hi');
        // 1. Check if user exists
        const employee = await Employee.findById(id);

        if (!employee) {
            console.log("Employee not found");
            return res.status(404).json({
                status: 'fail',
                message: 'Employee not found'
            });
        }

        // 2. Prepare update object with only provided fields
        const updateData = {};
        if (name) updateData.name = name;
        if (email) updateData.email = email;
        if (department) updateData.department = department;
        if (joiningDate) updateData.joiningDate = joiningDate;

        // 3. Handle designation changes with authorization checks
        if (designation) {
            // Only Admin can update Manager/HR roles

            if (["Manager", "HR"].includes(designation) && updater.designation !== "Admin") {
                console.log("Only Admin can update Manager or HR roles");
                return res.status(403).json({
                    status: 'fail',
                    message: 'Only Admin can update Manager or HR roles'
                });
            }

            // Only HR can update Employee roles
            if (designation === "Employee" && updater.designation !== "HR") {
                console.log("Only HR can update Employee accounts");
                return res.status(403).json({
                    status: 'fail',
                    message: 'Only HR can update Employee accounts'
                });
            }

            // Prevent Admin role updates
            if (designation === "Admin") {
                console.log("Admin role cannot be updated");
                return res.status(403).json({
                    status: 'fail',
                    message: 'Admin role cannot be updated'
                });
            }

            // Prevent users from promoting themselves
            if (id === updater._id.toString() && designation !== updater.designation) {
                console.log("You cannot change your own role");
                return res.status(403).json({
                    status: 'fail',
                    message: 'You cannot change your own role'
                });
            }

            updateData.designation = designation;
        }

        // 4. Update user with only the provided fields
        console.log("Updating employee with data:", updateData);
        const updatedEmployee = await Employee.findByIdAndUpdate(
            id,
            updateData,
            { new: true, runValidators: true }
        );
        console.log("Updated employee:", updatedEmployee);

        res.status(200).json({
            status: 'success',
            data: {
                user: updatedEmployee
            }
        });

    } catch (err) {
        res.status(500).json({
            status: 'fail',
            message: err.message
        });
    }
};