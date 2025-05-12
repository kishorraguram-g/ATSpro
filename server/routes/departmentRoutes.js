const express = require('express');
const router = express.Router();
const teamController = require('../controllers/teamController'); // Correct import
const { staffProtect } = require('../middlewares/authMiddleware'); // Ensure JWT auth middleware
const checkRole = require('../middlewares/checkRole');

// Define routes
router.post('/create', staffProtect, teamController.createTeam);
router.post('/add-employee', staffProtect, teamController.addEmployeesToTeam);
router.post('/add-manager', staffProtect, teamController.addManagerToTeam);
router.get('/allteams', staffProtect,checkRole(["HR","Admin"]), teamController.getTeams);
router.get('/team-employees', staffProtect, teamController.getTeamEmployees);
router.get('/team-manager', staffProtect, teamController.getTeamManager);
router.delete('/delete-team', staffProtect, teamController.deleteTeam);
router.get('/all-teams', staffProtect, checkRole(["HR","Admin"]), teamController.getAllTeams);
router.get('/is-employee-in-team', staffProtect, teamController.isEmployeeAssigned);

module.exports = router;
