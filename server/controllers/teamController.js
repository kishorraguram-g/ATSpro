const Team = require('../models/DepartmentModel'); // Updated import
const Employee = require('../models/EmployeeModel');

exports.createTeam = async (req, res) => {
    try {
        const user = req.user;
        if (!user || !['Admin', 'HR'].includes(user.designation)) {
            return res.status(403).json({
                status: "fail",
                message: "Only Admin or HR can create teams"
            });
        }

        const { teamName, department } = req.body;
        if (!teamName || !department) {
            return res.status(400).json({
                status: "fail",
                message: "Please provide team name and department"
            });
        }

        const existingTeam = await Team.findOne({ name: teamName, department });
        if (existingTeam) {
            return res.status(400).json({
                status: 'fail',
                message: 'Team with this name already exists'
            });
        }

        const newTeam = await Team.create({
            name: teamName,
            department: department
        });

        res.status(201).json({
            status: 'success',
            message: 'Team created successfully',
            data: newTeam
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.addEmployeesToTeam = async (req, res) => {
    try {
        const { teamId, employeeId } = req.body;

        const employee = await Employee.findById(employeeId);
        const validDesignations = ['Developer', 'Lead Developer', 'QA', 'Tech Support', 'UX/UI Designer'];

        if (!employee || !validDesignations.includes(employee.designation)) {
            return res.status(400).json({
                status: 'fail',
                message: 'Employee not valid or not found'
            });
        }

        const updatedTeam = await Team.findByIdAndUpdate(
            teamId,
            { $addToSet: { members: employeeId } },
            { new: true, runValidators: true }
        );

        res.status(200).json({
            status: 'success',
            message: 'Employee added to the team successfully',
            data: updatedTeam
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.addManagerToTeam = async (req, res) => {
    try {
        const { teamId, managerId } = req.body;

        const manager = await Employee.findById(managerId);
        if (!manager || !['Manager', 'Project Manager', 'Lead Developer'].includes(manager.designation)) {
            return res.status(400).json({
                status: 'fail',
                message: 'Manager not found or not valid'
            });
        }

        const team = await Team.findById(teamId);
        if (!team) {
            return res.status(404).json({ status: 'fail', message: 'Team not found' });
        }

        if (team.manager) {
            return res.status(400).json({
                status: 'fail',
                message: 'This team already has a manager'
            });
        }

        team.manager = managerId;
        await team.save();

        res.status(200).json({
            status: 'success',
            message: 'Manager assigned successfully',
            data: team
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.getTeams = async (req, res) => {
    try {
        const user = req.user;
        if (!['Admin', 'HR'].includes(user.designation)) {
            return res.status(403).json({
                status: "fail",
                message: "Only Admin or HR can get teams"
            });
        }
        const department = req.body.department;
        const teams = await Team.find();

        if (!teams.length) {
            return res.status(404).json({
                status: 'fail',
                message: 'No teams found'
            });
        }

        res.status(200).json({
            status: 'success',
            message: 'Department teams fetched successfully',
            data: teams
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.getTeamEmployees = async (req, res) => {
    try {
        const user = req.user;
        const userTeamName = req.body.teamName;
        console.log(userTeamName)
        const team = await Team.findOne({ name: userTeamName });
        if (!team) {
            return res.status(404).json({ status: 'fail', message: 'Team not found' });
        }

        const validDesignations = ['Developer', 'Lead Developer', 'QA', 'Tech Support', 'UX/UI Designer'];

        if (validDesignations.includes(user.designation)) {
            const isMember = team.members.includes(user._id);
            if (!isMember) {
                return res.status(403).json({
                    status: 'fail',
                    message: 'You can only view members of your own team'
                });
            }
        }

        const employees = await Employee.find({
            _id: { $in: team.members },
            designation: { $in: validDesignations }
        }).select('name');

        res.status(200).json({
            status: 'success',
            teamName: team.name,
            members: employees
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.getTeamManager = async (req, res) => {
    try {
        const user = req.user;
        const { teamName } = req.body;

        const team = await Team.findOne({ name: teamName });
        if (!team) {
            return res.status(404).json({
                status: 'fail',
                message: 'Team not found'
            });
        }

        if (['Developer', 'Lead Developer', 'QA', 'Tech Support', 'UX/UI Designer'].includes(user.designation)) {
            if (!team.members.includes(user._id)) {
                return res.status(403).json({
                    status: 'fail',
                    message: 'You can only view your own team manager'
                });
            }
        }

        const manager = await Employee.findById(team.manager).select('name designation');

        res.status(200).json({
            status: 'success',
            manager: manager || 'No manager assigned'
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.deleteTeam = async (req, res) => {
    try {
        const { designation, department } = req.user;
        const { deleteTeam } = req.body;

        if (!['Admin', 'HR'].includes(designation)) {
            return res.status(403).json({
                status: 'fail',
                message: 'Only Admin or HR can delete a team'
            });
        }
        const team = await Team.findOne({ name: deleteTeam });
        if (!team) {
            return res.status(404).json({
                status: 'fail',
                message: 'Team not found'
            });
        }


        if (team.department !== department && !(designation == 'Admin' || designation == 'HR')) {
            return res.status(403).json({
                status: 'fail',
                message: 'You can only delete teams in your own department'
            });
        }

        const deletedTeam = await Team.findOneAndDelete({ name: deleteTeam });

        res.status(202).json({
            status: 'success',
            message: 'Team deleted successfully',
            deletedTeam
        });

    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
};

exports.getAllTeams = async (req, res) => {
    try {
        const user = req.user;
        if (!['Admin', 'HR'].includes(user.designation)) {
            return res.status(403).json({
                status: "fail",
                message: "Only Admin or HR can get all teams"
            });
        }

        const teams = await Team.find({}).populate('members', 'name designation').populate('manager', 'name designation');
        if (!teams.length) {
            return res.status(404).json({
                status: 'fail',
                message: 'No teams found'
            });
        }

        res.status(200).json({
            status: 'success',
            message: 'All teams fetched successfully',
            data: teams
        });
    } catch (err) {
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }
}

exports.isEmployeeAssigned = async (req, res) => {
    try{
        const { email } = req.body;
        const employee = await Employee.findOne({ email });
        if (!employee) {
            return res.status(404).json({
                status: 'fail',
                message: 'Employee not found'
            });
        }

        const objid=employee._id;
        const empid=objid.toString();
        console.log(empid);
        let teams= await Team.find();
        console.log(teams);
        teams = teams.filter(team => team.members.includes(empid));
        if (teams.length === 0) {
            return res.status(404).json({
                status: 'fail',
                message: 'Employee is not assigned to any team'
            });
        }
        res.status(200).json({
            status: 'success',
            message: 'Employee is assigned to the following teams',
            data: teams
        });
    }
    catch(err){
        res.status(500).json({
            status: "fail",
            message: err.message
        });
    }   
}