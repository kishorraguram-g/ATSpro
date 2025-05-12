const mongoose = require('mongoose');

const Departmemtschema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    department: {
        type: String,
        required: true
    },
    manager: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Employee'
    },
    members: [
        {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'Employee'
        }
    ]
});

const Department = mongoose.model('Departments', Departmemtschema);

module.exports = Department;
