const mongoose = require('mongoose');

const AttendanceSchema = new mongoose.Schema({
    employee: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Employee',
        required: true
    },
    team:{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Departments',
        required: true
    },
    date: {
        type: Date,
        required: true,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['Present', 'Absent', 'On Leave', 'Remote'],
        required: true
    },
    attendanceType: {
        type: String,
        enum: ['Regular', 'Remote', 'Sick Leave', 'Other'],
        default: 'Regular'
    }
}, { timestamps: true }); // Adds createdAt and updatedAt fields

AttendanceSchema.index({ employee: 1, date: 1 }, { unique: true });

const Attendance = mongoose.model('Attendance', AttendanceSchema);

module.exports = Attendance;
