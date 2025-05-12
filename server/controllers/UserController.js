const Employee = require('../models/EmployeeModel');

exports.getAllUsers=async(req, res) => {
    try {
         let users = await Employee.find({});
        const para=req.query.employeeId;
        if(para){
            return res.status(200).json({
                status: 'success',
                data: users
            });
        }
        console.log(para);
         users = users.filter(user => {
            const cleanDesignation = user.designation.trim().replace(/^"(.*)"$/, '$1'); // removes surrounding quotes
            return cleanDesignation !== 'Admin' && cleanDesignation !== 'HR';
        });

        // console.log(users)
        if (!users) {
            return res.status(404).json({
                status: 'fail',
                message: 'No users found'
            });
        }
        res.status(200).json({
            status: 'success',
            data: users
        });
    } catch (err) {
        res.status(500).json({
            status: 'fail',
            message: err.message
        });
    }
};




exports.deleteUser = async (req, res) => {
    try {
        const userId = req.params.id;
        // const employee=await Employee.find(userId);
        // console.log(employee)
        

        const user = await Employee.findByIdAndDelete(userId);
        
        if (!user) {
            return res.status(404).json({
                status: 'fail',
                message: 'User not found'
            });
        }
        res.status(200).json({
            status: 'success',
            message: 'User deleted successfully'
        });
    } catch (err) {
        res.status(500).json({
            status: 'fail',
            message: err.message
        });
    }
}

