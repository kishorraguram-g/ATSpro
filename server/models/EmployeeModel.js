const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const EmployeeSchema = mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true,
        select: false
    },
    employeeId: {
        type: String
    },
    department: {
        type: String,
        required: true
    },
    designation: {
        type: String,
        enum: [
            'Developer', 'Lead Developer', 'Project Manager', 
            'HR', 'Admin', 'Manager', 'QA', 'Tech Support', 
            'UX/UI Designer', 'System Architect'
        ], 
        required: true
    },
    status: {
        type: String,
        enum: ['Active', 'Inactive'],
        default: 'Active'
    },
    joiningDate: {
        type: Date,
        required: true
    },
    lastLogin: {
        type: Date,
    },
    passwordChangedAt: {
        type: Date,
    },
    rolePermissions: {
        type: Map,
        of: Boolean,
        default: {
            canMarkAttendance: false,
            canViewAttendance: false,
            canAssignTasks: false,
            canViewReports: false,
            canAccessSensitiveData: false,
            canManageEmployees: false
        }
    }
}, { timestamps: true });

// Password hashing before saving
EmployeeSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    // this.password = await bcrypt.hash(this.password, 12);
    this.password=this.password;
    if (!this.isNew || this.employeeId) return next();
  // Generate ID format: EMP-YYYY-XXXX (4 random digits)
    const randomNum = Math.floor(1000 + Math.random() * 9000);
    this.employeeId = `EMP-${new Date().getFullYear()}-${randomNum}`;
    next();
});

// Compare password
// EmployeeSchema.methods.comparePassword = async function (candidatePassword, userPassword) {
//     return await bcrypt.compare(candidatePassword, userPassword);
// };

EmployeeSchema.methods.comparePassword = async function (candidatePassword, userPassword) {
    return candidatePassword === userPassword;
};

// Check if the password was changed after JWT issued
EmployeeSchema.methods.changePasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
        return JWTTimestamp < changedTimestamp;
    }
    return false;
};

const Employee = mongoose.model('Employee', EmployeeSchema);
module.exports = Employee;
