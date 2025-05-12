const Team = require('../models/DepartmentModel'); // Updated model import for Team
const Employee = require('../models/EmployeeModel');
const mongoose = require('mongoose'); // Import mongoose for ObjectId validation
const Attendance = require('../models/AttendenceModel'); // Assuming Attendance model exists

// Create attendance
exports.createAttendance = async (req, res) => {
    try {
        const { employeeId, teamId, date, status, attendanceType } = req.body;
        if(!date){
            date=new Date();
        }
        // Find employee by ID
        const employee = await Employee.findById(employeeId);
        if (!employee) {
            return res.status(404).json({
                status: 'fail',
                message: 'Employee not found'
            });
        }

        // Find team by ID
        const team = await Team.findById(teamId);
        if (!team) {
            return res.status(404).json({
                status: 'fail',
                message: 'Team not found'
            });
        }

        // Create attendance record
        const attendance = new Attendance({
            employee: employeeId,
            team: teamId,
            date,
            status,
            attendanceType
        });

        await attendance.save();

        res.status(201).json({
            status: 'success',
            message: 'Attendance recorded successfully',
            data: attendance
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

// Get attendance for an employee by team
exports.getAttendance = async (req, res) => {
    try {
        const { employeeId, teamId, date } = req.body;

        // Find employee and team
        const employee = await Employee.findById(employeeId);
        if (!employee) {
            return res.status(404).json({
                status: 'fail',
                message: 'Employee not found'
            });
        }

        const team = await Team.findById(teamId);
        if (!team) {
            return res.status(404).json({
                status: 'fail',
                message: 'Team not found'
            });
        }

        // Find attendance for the employee and team
        const attendance = await Attendance.findOne({ employee: employeeId, team: teamId, date });
        console.log(attendance)

        if (!attendance) {
            return res.status(404).json({
                status: 'fail',
                message: 'Attendance record not found'
            });
        }

        res.status(200).json({
            status: 'success',
            data: attendance
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

// Update attendance status
exports.updateAttendance = async (req, res) => {
    try {
        const { attendanceId, status, attendanceType } = req.body;

        // Find the attendance record by ID
        const attendance = await Attendance.findById(attendanceId);
        if (!attendance) {
            return res.status(404).json({
                status: 'fail',
                message: 'Attendance record not found'
            });
        }

        // Update attendance details
        attendance.status = status || attendance.status;
        attendance.attendanceType = attendanceType || attendance.attendanceType;

        await attendance.save();

        res.status(200).json({
            status: 'success',
            message: 'Attendance updated successfully',
            data: attendance
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

// Get attendance summary for a team
exports.getTeamAttendanceSummary = async (req, res) => {
    try {
        let employeeId = req.params.id;
        console.log(employeeId) 
        // employeeId=JSON.parse(employeeId);
        console.log('hi')
        let teams=await Team.find().populate('manager');
        console.log(teams)
        console.log('hi')
        let temId;
        console.log('hello1')
        console.log(teams.length)
        let Teams=[];
        for(let i=0;i<teams.length;i++){
            if(!teams[i].manager){
                continue;
            }
            console.log(teams[i]._id)
            console.log('hi');
            if(teams[i].manager._id==employeeId){
                console.log('hello2');
                console.log(teams[i]);
                Teams.push(teams[i]);
                temId=teams[i]._id;
                break;
                
            }

            console.log(teams[i]);            
        }
            console.log('exited')
        console.log('hello')
        console.log(temId)
        if(!temId){
            return res.status(404).json({
                status:'fail',
                message:'Team not found'
            });
        }
        const attendanceRecords = await Attendance.find({ team: temId }).populate('employee', 'name'); // Populate employee details
        // console.log(temId);
        res.status(200).json({
            status: 'success',
            data: attendanceRecords
        });

    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

// Get attendance summary for a specific employee
exports.getEmployeeAttendanceSummary = async (req, res) => {
    try {
        const { employeeId } = req.body;

        // Find employee by ID
        const employee = await Employee.findById(employeeId);
        if (!employee) {
            return res.status(404).json({
                status: 'fail',
                message: 'Employee not found'
            });
        }

        // Get all attendance records for the employee
        const attendanceRecords = await Attendance.find({ employee: employeeId });

        if (!attendanceRecords.length) {
            return res.status(404).json({
                status: 'fail',
                message: 'No attendance records found for the employee'
            });
        }

        res.status(200).json({
            status: 'success',
            data: attendanceRecords
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};


exports.getMyAttendance = async (req, res) => {
    try {
      const employeeId = req.params.id;
      
    //   if (!mongoose.Types.ObjectId.isValid(employeeId)) {
    //     return res.status(400).json({ 
    //       status: 'fail',
    //       message: 'Invalid employee ID format' 
    //     });
    //   }
    //   
    const re=await Attendance.find();
    // console.log(re)
    const ObjectId = require('mongoose').Types.ObjectId;
    const objectId = new ObjectId(employeeId);
    console.log('hi');
    const records = await Attendance.find({
        employee: objectId,
      }).populate('team');   
      res.status(200).json({ status: 'success', data: records });
      
    } catch (err) {
      res.status(500).json({ status: "fail", message: err.message });
    }
  }


  exports.getAllSummary = async (req, res) => {
    try {
        // console.log(re)
    const records = await Attendance.find().populate('team employee');
     
    res.status(200).json({ status: 'success', data: records });

      
        
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.createAttendanceByemail=async(req,res)=>{
    try{
        let {email,date, status, attendanceType }=req.body;
        if(!date){
            date=new Date();
        }
        let employee=await Employee.findOne({email:email});
        console.log(employee)
        if(!employee){
            return res.status(404).json({
                status:'fail',
                message:'Employee not found'
            });
        }
        let employeeId=employee._id;
        let team = await Team.find();
        let teams=team;
        console.log(teams)
        let temId;
        let members=[];

        //if employee
        for(let i=0;i<teams.length;i++){
            let memberIds = teams[i].members.map(member => member.toString());
            console.log(memberIds);
            for(let j=0;j<memberIds.length;j++){
                console.log(memberIds[j]+" "+employeeId.toString())
                if(memberIds[j]===employeeId.toString()){
                    temId=teams[i]._id;
                    members=teams[i].members;
                    break;
                }
            }
            if(temId){
                break;
            }
        }
        if(temId){
        temId=temId.toString();
        console.log(temId)
        }
        //if manager
        if(!temId){
            for(let i=0;i<teams.length;i++){
                console.log(teams[i].manager.toString());
                temId=teams[i]._id;
                break;
            }
        }
        
        if(!temId){
            return res.status(404).json({
                status:'fail',
                message:'Team not found'
            });
        }
        const attendance = new Attendance({
            employee: employeeId,
            team: temId,
            date,
            status,
            attendanceType
        });
        await attendance.save();

        res.status(200).json({
            status:'success',
            data:attendance
        });



    }
    catch(err){
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
}
exports.deleteAttendanceByemail=async(req,res)=>{
    try{
        let {email,date, status, attendanceType }=req.body;
        if(!date){
            date=new Date();
        }
        let employee=await Employee.findOne({email:email});
        if(!employee){
            return res.status(404).json({
                status:'fail',
                message:'Employee not found'
            });
        }
        let employeeId=employee._id;
        let team = await Team.find();
        let teams=team;
        console.log(teams)
        let temId;
        let members=[];
        for(let i=0;i<teams.length;i++){
            let memberIds = teams[i].members.map(member => member.toString());
            console.log(memberIds);
            for(let j=0;j<memberIds.length;j++){
                console.log(memberIds[j]+" "+employeeId.toString())
                if(memberIds[j]===employeeId.toString()){
                    temId=teams[i]._id;
                    members=teams[i].members;
                    break;
                }
            }
            if(temId){
                break;
            }

        }
        if(!temId){   
            for(let i=0;i<teams.length;i++){
                console.log(teams[i].manager.toString());
                temId=teams[i]._id;
                break;
            }
        }
        temId=temId.toString();
        console.log(temId)
        
        if(!temId){
            return res.status(404).json({
                status:'fail',
                message:'Team not found'
            });
        }
        await Attendance.findOneAndDelete({
            employee: employeeId,
            date: {
              $gte: new Date(new Date(date).setHours(0, 0, 0, 0)),
              $lte: new Date(new Date(date).setHours(23, 59, 59, 999))
            }
          });

        res.status(200).json({
            status:'success',
            message:'Attendance deleted successfully'
        });



    }
    catch(err){
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
}