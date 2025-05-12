import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { FiLogOut, FiUsers, FiCalendar, FiHome, FiUserPlus, FiUser, FiSettings, FiPieChart, FiClock } from 'react-icons/fi';
import { toast } from 'react-toastify';

const HRDashboard = () => {
  const [activeTab, setActiveTab] = useState('teams');
  const [teams, setTeams] = useState([]);
  const [attendanceData, setAttendanceData] = useState([]);
  const [loading, setLoading] = useState(true); // Changed initial state to true
  const navigate = useNavigate();

  // Fetch all teams data
  const fetchTeams = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      if (!token) {
        navigate('/');
        return;
      }
      
      const response = await axios.get('http://localhost:4000/department/all-teams', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setTeams(response.data.data || []);
    } catch (error) {
      toast.error('Failed to fetch teams');
    } finally {
      setLoading(false);
    }
  };

  // Fetch attendance summary
  const fetchAttendanceSummary = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:4000/attendance/all-attendance', {
        headers: { Authorization: `Bearer ${token}` }
      });
      console.log(response.data);
      setAttendanceData(response.data.data || []);
    } catch (error) {
      toast.error('Failed to fetch attendance data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Check authentication first
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/');
      return;
    }

    // Then fetch initial data based on active tab
    if (activeTab === 'teams') {
      fetchTeams();
    } else if (activeTab === 'attendance') {
      fetchAttendanceSummary();
    } else {
      setLoading(false);
    }
  }, [activeTab, navigate])

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    navigate('/');
    toast.success('Logged out successfully');
  };

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewTab teams={teams} attendanceData={attendanceData} />;
      case 'teams':
        return <TeamsTab teams={teams} loading={loading} refreshTeams={fetchTeams} />;
      case 'attendance':
        return <AttendanceTab data={attendanceData} loading={loading} />;
      case 'employees':
        return <EmployeesTab />;
      default:
        return <TeamsTab teams={teams} loading={loading} refreshTeams={fetchTeams} />;
    }
  };

  return (
    <div className="flex h-screen bg-gray-50">
      {/* Sidebar */}
      <div className="w-64 bg-white shadow-md">
        <div className="p-4 border-b border-gray-200">
          <h1 className="text-xl font-bold text-gray-800">HR Dashboard</h1>
        </div>
        <nav className="mt-6">
          {/* <NavItem 
            icon={<FiHome size={18} />} 
            text="Overview" 
            active={activeTab === 'overview'}
            onClick={() => setActiveTab('overview')}
          /> */}
          <NavItem 
            icon={<FiUsers size={18} />} 
            text="Team Management" 
            active={activeTab === 'teams'}
            onClick={() => setActiveTab('teams')}
          />
          <NavItem 
            icon={<FiCalendar size={18} />} 
            text="Attendance" 
            active={activeTab === 'attendance'}
            onClick={() => setActiveTab('attendance')}
          />
          <NavItem 
            icon={<FiUser size={18} />} 
            text="Employees" 
            active={activeTab === 'employees'}
            onClick={() => setActiveTab('employees')}
          />
          {/* <NavItem 
            icon={<FiPieChart size={18} />} 
            text="Reports" 
            active={activeTab === 'reports'}
            onClick={() => setActiveTab('reports')}
          /> */}
        </nav>
        <div className="absolute bottom-0 w-full p-4">
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 w-52 p-2 text-red-600 hover:bg-red-50 rounded-lg"
          >
            <FiLogOut size={18} />
            <span>Logout</span>
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-8">
        <div className="bg-white rounded-lg shadow-sm p-6">
          {renderTabContent()}
        </div>
      </div>
    </div>
  );
};

// Component for navigation items
const NavItem = ({ icon, text, active, onClick }) => (
  <button
    onClick={onClick}
    className={`flex items-center gap-3 w-full p-3 ${active ? 'bg-blue-50 text-blue-600' : 'text-gray-600 hover:bg-gray-100'}`}
  >
    {icon}
    <span>{text}</span>
  </button>
);

// Tab Components
const OverviewTab = ({ teams, attendanceData }) => (
  <div>
    <h2 className="text-xl font-semibold mb-6">Dashboard Overview</h2>
    
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <StatCard 
        title="Total Teams" 
        value={teams.length} 
        icon={<FiUsers className="text-blue-500" size={24} />} 
      />
      <StatCard 
        title="Employees Tracked" 
        value={teams.reduce((acc, team) => acc + team.members.length, 0)} 
        icon={<FiUser className="text-green-500" size={24} />} 
      />
      <StatCard 
        title="Attendance Records" 
        value={attendanceData.length} 
        icon={<FiCalendar className="text-purple-500" size={24} />} 
      />
    </div>

    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      <div className="bg-white p-4 rounded-lg border border-gray-200">
        <h3 className="font-medium mb-3">Recent Teams</h3>
        {teams.slice(0, 5).map(team => (
          <div key={team._id} className="flex items-center justify-between py-2 border-b border-gray-100">
            <span>{team.name}</span>
            <span className="text-sm text-gray-500">{team.members.length} members</span>
          </div>
        ))}
      </div>
      <div className="bg-white p-4 rounded-lg border border-gray-200">
        <h3 className="font-medium mb-3">Attendance Summary</h3>
        {/* Add attendance summary chart here */}
      </div>
    </div>
  </div>
);

const TeamsTab = ({ teams: initialTeams, loading, refreshTeams }) => {
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showAddMemberModal, setShowAddMemberModal] = useState(false);
  const [showAddManagerModal, setShowAddManagerModal] = useState(false);
  const [selectedTeam, setSelectedTeam] = useState(null);
  const [teams, setTeams] = useState(initialTeams);
  const [formData, setFormData] = useState({
    teamName: '',
    department: '',
    employeeEmail: '',
    managerEmail: ''
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [employees, setEmployees] = useState([]);
  const [managers, setManagers] = useState([]);

  // Sync teams with props
  useEffect(() => {
    setTeams(initialTeams);
  }, [initialTeams]);

  // Fetch employees for member addition
  useEffect(() => {
    if (showAddMemberModal && selectedTeam) {
      const fetchEmployees = async () => {
        try {
          const response = await axios.get('http://localhost:4000/employees', {
            headers: {
              'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
          });
      
          const employeeList = response.data.data; // Access the actual array
          console.log(employeeList);
      
          setEmployees(employeeList.filter(emp =>
            ['Developer', 'Lead Developer', 'QA', 'Tech Support', 'UX/UI Designer'].includes(emp.designation)
          ));
        } catch (error) {
          console.error('Error fetching employees:', error);
        }
      };
      
      fetchEmployees();      
    }
  }, [showAddMemberModal, selectedTeam]);

  // Fetch managers
  useEffect(() => {
    if (showAddManagerModal && selectedTeam) {
      const fetchManagers = async () => {
        try {
          const response = await axios.get('http://localhost:4000/employees', {
            headers: {
              'Authorization': `Bearer ${localStorage.getItem('token')}`
            }
          });
      
          const employeeList = response.data.data; // Access the array of employees
          console.log(employeeList);
      
          setManagers(employeeList.filter(emp => 
            ['Manager', 'Project Manager', 'Lead Developer'].includes(emp.designation)
          ));
        } catch (error) {
          console.error('Error fetching managers:', error);
        }
      };
      
      fetchManagers();      
    }
  }, [showAddManagerModal, selectedTeam]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      await axios.post('http://localhost:4000/department/create', {
        teamName: formData.teamName,
        department: formData.department
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      setShowCreateModal(false);
      refreshTeams();
      setFormData({ teamName: '', department: '' });
    } catch (error) {
      console.error('Error creating team:', error);
      alert(`Error: ${error.response?.data?.message || 'Failed to create team'}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddMember = async (employeeId) => {
    setIsSubmitting(true);
    try {
      await axios.post('http://localhost:4000/department/add-employee', {
        teamId: selectedTeam._id,
        employeeId
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      setShowAddMemberModal(false);
      refreshTeams();
    } catch (error) {
      console.error('Error adding member:', error);
      alert(`Error: ${error.response?.data?.message || 'Failed to add member'}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAddManager = async (managerId) => {
    setIsSubmitting(true);
    try {
      await axios.post('http://localhost:4000/department/add-manager', {
        teamId: selectedTeam._id,
        managerId
      }, {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      setShowAddManagerModal(false);
      refreshTeams();
    } catch (error) {
      console.error('Error adding manager:', error);
      alert(`Error: ${error.response?.data?.message || 'Failed to add manager'}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteTeam = async (teamId) => {
    if (!window.confirm('Are you sure you want to delete this team?')) return;
    
    try {
      await axios.delete('http://localhost:4000/department/delete-team', {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        data: { deleteTeam: teams.find(t => t._id === teamId).name }
      });
      window.location.reload();
      refreshTeams();
    } catch (error) {
      console.error('Error deleting team:', error);
      alert(`Error: ${error.response?.data?.message || 'Failed to delete team'}`);
    }
  };

  return (
    <div className="p-4">
      {/* Create Team Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Create New Team</h2>
                <button 
                  onClick={() => setShowCreateModal(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <form onSubmit={handleCreateTeam}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Team Name</label>
                    <input
                      type="text"
                      name="teamName"
                      value={formData.teamName}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Department</label>
                    <input
                      type="text"
                      name="department"
                      value={formData.department}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>
                </div>

                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setShowCreateModal(false)}
                    className="px-4 py-2 border rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? 'Creating...' : 'Create Team'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Add Member Modal */}
      {showAddMemberModal && selectedTeam && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Add Members to {selectedTeam.name}</h2>
                <button 
                  onClick={() => setShowAddMemberModal(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                <div className="max-h-60 overflow-y-auto">
                  {employees.length > 0 ? (
                    employees.map(employee => (
                      <div key={employee._id} className="flex items-center justify-between p-2 border-b">
                        <span>{employee.name} ({employee.designation})</span>
                        <button
                          onClick={() => handleAddMember(employee._id)}
                          className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                          disabled={isSubmitting}
                        >
                          Add
                        </button>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500">No employees available</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Manager Modal */}
      {showAddManagerModal && selectedTeam && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Add Manager to {selectedTeam.name}</h2>
                <button 
                  onClick={() => setShowAddManagerModal(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <div className="space-y-4">
                <div className="max-h-60 overflow-y-auto">
                  {managers.length > 0 ? (
                    managers.map(manager => (
                      <div key={manager._id} className="flex items-center justify-between p-2 border-b">
                        <span>{manager.name} ({manager.designation})</span>
                        <button
                          onClick={() => handleAddManager(manager._id)}
                          className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                          disabled={isSubmitting}
                        >
                          Assign
                        </button>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500">No managers available</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Team Management UI */}
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-xl font-semibold">Team Management</h2>
        <button 
          onClick={() => setShowCreateModal(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
        >
          Create New Team
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-40">
          <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : teams.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-40 bg-gray-50 rounded-lg">
          <p className="text-gray-500 text-lg mb-4">No teams found</p>
          <button 
            onClick={() => setShowCreateModal(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700"
          >
            Create Your First Team
          </button>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Team Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Department</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Members</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Manager</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {teams.map(team => (
                <tr key={team._id}>
                  <td className="px-6 py-4 whitespace-nowrap">{team.name}</td>
                  <td className="px-6 py-4 whitespace-nowrap">{team.department}</td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {team.members.length}
                    <button 
                      onClick={() => {
                        setSelectedTeam(team);
                        setShowAddMemberModal(true);
                      }}
                      className="ml-2 text-blue-600 hover:text-blue-800"
                    >
                      (Add)
                    </button>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {team.manager ? team.manager.name : 'Not assigned'}
                    {!team.manager && (
                      <button 
                        onClick={() => {
                          setSelectedTeam(team);
                          setShowAddManagerModal(true);
                        }}
                        className="ml-2 text-blue-600 hover:text-blue-800"
                      >
                        (Assign)
                      </button>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <button 
                      onClick={() => handleDeleteTeam(team._id)}
                      className="text-red-600 hover:text-red-800"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
// import React, { useState } from 'react';
// import axios from 'axios';
const AttendanceTab = ({ data, loading }) => {
  const [selectedDate, setSelectedDate] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [formData, setFormData] = useState({
    employeeEmail: '',
    date: selectedDate || new Date().toISOString().split('T')[0],
    status: 'Present',
    attendanceType: 'Regular'
  });
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [filteredData, setFilteredData] = useState([]);
  const [isDeleting, setIsDeleting] = useState(false);
  const [employees, setEmployees] = useState([]);

  // Initialize filtered data with null checks
  useEffect(() => {
    const validData = Array.isArray(data) ? data.filter(record => 
      record && record.employee && record.team
    ) : [];
    setFilteredData(validData);
  }, [data]);

  // Filter data by date
  useEffect(() => {
    if (selectedDate) {
      const filtered = data.filter(record => {
        if (!record || !record.date) return false;
        const recordDate = new Date(record.date).toISOString().split('T')[0];
        return recordDate === selectedDate;
      });
      setFilteredData(filtered);
    } else {
      setFilteredData(data);
    }
  }, [selectedDate, data]);

  // Update form date when selectedDate changes
  useEffect(() => {
    if (selectedDate) {
      setFormData(prev => ({ ...prev, date: selectedDate }));
    }
  }, [selectedDate]);

  // Fetch employees for the dropdown
  useEffect(() => {
    const fetchEmployees = async () => {
      try {
        const response = await axios.get('http://localhost:4000/employees', {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });
        setEmployees(response.data.data || []);
      } catch (error) {
        console.error('Error fetching employees:', error);
      }
    };
    
    if (isModalOpen) {
      fetchEmployees();
    }
  }, [isModalOpen]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const response = await axios.post(
        'http://localhost:4000/attendance/attendancebyemail',
        {
          email: formData.employeeEmail,
          date: formData.date,
          status: formData.status,
          attendanceType: formData.attendanceType
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        }
      );
      
      toast.success('Attendance record created successfully');
      setIsModalOpen(false);
      setFormData({
        employeeEmail: '',
        date: selectedDate || new Date().toISOString().split('T')[0],
        status: 'Present',
        attendanceType: 'Regular'
      });
      // Trigger a refresh in parent component
      window.location.reload();
    } catch (error) {
      console.error('Error creating attendance:', error);
      toast.error(`Error: ${error.response?.data?.message || 'Failed to create record'}`);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async (record) => {
    if (!record?.employee?.email || !window.confirm('Are you sure you want to delete this attendance record?')) {
      return;
    }

    setIsDeleting(true);
    try {
      await axios.delete('http://localhost:4000/attendance/attendancebyemail', {
        headers: {  
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        data: {
          email: record.employee.email,
          date: record.date
        }
      });

      // Optimistically remove the deleted record from the UI
      setFilteredData(prev => prev.filter(item => item._id !== record._id));
      toast.success('Attendance record deleted successfully');
    } catch (error) {
      console.error('Error deleting attendance:', error);
      toast.error(`Error: ${error.response?.data?.message || 'Failed to delete record'}`);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <div className="p-4">
      {/* Create Attendance Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Create Attendance Record</h2>
                <button 
                  onClick={() => setIsModalOpen(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <form onSubmit={handleSubmit}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Employee</label>
                    <select
                      name="employeeEmail"
                      value={formData.employeeEmail}
                      onChange={handleChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    >
                      <option value="">Select Employee</option>
                      {employees.map(employee => (
                        <option key={employee._id} value={employee.email}>
                          {employee.name} ({employee.email})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Date</label>
                    <input
                      type="date"
                      name="date"
                      value={formData.date}
                      onChange={handleChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                    <select
                      name="status"
                      value={formData.status}
                      onChange={handleChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    >
                      <option value="Present">Present</option>
                      <option value="Absent">Absent</option>
                      <option value="On Leave">On Leave</option>
                      <option value="Remote">Remote</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Type</label>
                    <select
                      name="attendanceType"
                      value={formData.attendanceType}
                      onChange={handleChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    >
                      <option value="Regular">Regular</option>
                      <option value="Remote">Remote</option>
                      <option value="Sick Leave">Sick Leave</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                </div>

                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setIsModalOpen(false)}
                    className="px-4 py-2 border rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                    disabled={isSubmitting}
                  >
                    {isSubmitting ? 'Creating...' : 'Create Record'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Attendance Table Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-semibold">Attendance Records</h2>
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-4 w-full sm:w-auto">
          <input
            type="date"
            value={selectedDate}
            onChange={(e) => setSelectedDate(e.target.value)}
            className="border p-2 rounded w-full sm:w-auto"
          />
          <button 
            onClick={() => setIsModalOpen(true)}
            className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 w-full sm:w-auto"
          >
            Create Record
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-40">
          <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : filteredData.length === 0 ? (
        <div className="bg-gray-50 rounded-lg p-8 text-center">
          <p className="text-gray-500 text-lg">No attendance records found</p>
          {selectedDate && (
            <button 
              onClick={() => setSelectedDate('')}
              className="mt-4 text-blue-600 hover:text-blue-800"
            >
              Clear date filter
            </button>
          )}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Employee</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Date</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Team</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredData.map(record => (
                <tr key={record._id}>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {record.employee?.name || 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {record.date ? new Date(record.date).toLocaleDateString() : 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className={`px-2 py-1 rounded-full text-xs ${
                      record.status === 'Present' ? 'bg-green-100 text-green-800' :
                      record.status === 'Absent' ? 'bg-red-100 text-red-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {record.status || 'N/A'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {record.attendanceType || 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    {record.team?.name || 'N/A'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <button 
                      onClick={() => handleDelete(record)}
                      className="text-red-600 hover:text-red-800 disabled:opacity-50"
                      disabled={isDeleting || !record.employee?.email}
                    >
                      {isDeleting ? 'Deleting...' : 'Delete'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
const EmployeesTab = () => {
  const [employees, setEmployees] = useState([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [currentEmployee, setCurrentEmployee] = useState(null);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    department: '',
    designation: '',
    joiningDate: new Date().toISOString().split('T')[0]
  });
  const filteredEmployees = employees.filter(employee => 
    !['Admin', 'HR', 'Manager','Project Manager',].includes(employee.designation)
  );
  // Fetch all employees
  const fetchEmployees = async () => {
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      const response = await axios.get('http://localhost:4000/employees', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      setEmployees(response.data.data || []);
    } catch (error) {
      toast.error('Failed to fetch employees');
      console.error('Error fetching employees:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEmployees();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleCreateEmployee = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      
      if (formData.password !== formData.confirmPassword) {
        toast.error('Passwords do not match');
        return;
      }

      const response = await axios.post(
        'http://localhost:4000/employees/create',
        formData,
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          }
        }
      );

      toast.success('Employee created successfully');
      setIsModalOpen(false);
      setFormData({
        name: '',
        email: '',
        password: '',
        confirmPassword: '',
        department: '',
        designation: '',
        joiningDate: new Date().toISOString().split('T')[0]
      });
      fetchEmployees();
    } catch (error) {
      console.error('Error creating employee:', error);
      toast.error(`Error: ${error.response?.data?.message || 'Failed to create employee'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleEditEmployee = (employee) => {
    setCurrentEmployee(employee);
    setFormData({
      name: employee.name,
      email: employee.email,
      password: '',
      confirmPassword: '',
      department: employee.department,
      designation: employee.designation,
      joiningDate: employee.joiningDate ? 
        new Date(employee.joiningDate).toISOString().split('T')[0] : 
        new Date().toISOString().split('T')[0]
    });
    setIsEditModalOpen(true);
  };

  const handleUpdateEmployee = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      
      // Only include password fields if they're not empty
      const updateData = { ...formData };
      if (!updateData.password) {
        delete updateData.password;
        delete updateData.confirmPassword;
      } else if (updateData.password !== updateData.confirmPassword) {
        toast.error('Passwords do not match');
        return;
      }

      const response = await axios.patch(
        `http://localhost:4000/employees/employees/${currentEmployee._id}`,
        updateData,
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          }
        }
      );

      toast.success('Employee updated successfully');
      setIsEditModalOpen(false);
      fetchEmployees();
    } catch (error) {
      console.error('Error updating employee:', error);
      toast.error(`Error: ${error.response?.data?.message || 'Failed to update employee'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteEmployee = async (id) => {
    if (!window.confirm('Are you sure you want to delete this employee?')) return;
    
    try {
      setLoading(true);
      const token = localStorage.getItem('token');
      await axios.delete(`http://localhost:4000/employees/employees/${id}`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      toast.success('Employee deleted successfully');
      fetchEmployees();
    } catch (error) {
      console.error('Error deleting employee:', error);
      toast.error(`Error: ${error.response?.data?.message || 'Failed to delete employee'}`);
    } finally {
      setLoading(false);
    }
  };

  const designationOptions = [
    'Developer', 'Lead Developer', 'Project Manager',
    'HR', 'Admin', 'Manager', 'QA', 'Tech Support',
    'UX/UI Designer', 'System Architect', 'Employee'
  ];

  return (
    <div className="p-4">
      {/* Create Employee Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Create New Employee</h2>
                <button 
                  onClick={() => setIsModalOpen(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <form onSubmit={handleCreateEmployee}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Full Name</label>
                    <input
                      type="text"
                      name="name"
                      value={formData.name}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
                    <input
                      type="password"
                      name="password"
                      value={formData.password}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Confirm Password</label>
                    <input
                      type="password"
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Department</label>
                    <input
                      type="text"
                      name="department"
                      value={formData.department}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Designation</label>
                    <select
                      name="designation"
                      value={formData.designation}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    >
                      <option value="">Select Designation</option>
                      {designationOptions.map(option => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Joining Date</label>
                    <input
                      type="date"
                      name="joiningDate"
                      value={formData.joiningDate}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>
                </div>

                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setIsModalOpen(false)}
                    className="px-4 py-2 border rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                    disabled={loading}
                  >
                    {loading ? 'Creating...' : 'Create Employee'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Edit Employee Modal */}
      {isEditModalOpen && currentEmployee && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
            <div className="p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl font-semibold">Edit Employee</h2>
                <button 
                  onClick={() => setIsEditModalOpen(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>
              
              <form onSubmit={handleUpdateEmployee}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Full Name</label>
                    <input
                      type="text"
                      name="name"
                      value={formData.name}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
                    <input
                      type="email"
                      name="email"
                      value={formData.email}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">New Password (leave blank to keep current)</label>
                    <input
                      type="password"
                      name="password"
                      value={formData.password}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
                    <input
                      type="password"
                      name="confirmPassword"
                      value={formData.confirmPassword}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Department</label>
                    <input
                      type="text"
                      name="department"
                      value={formData.department}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Designation</label>
                    <select
                      name="designation"
                      value={formData.designation}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    >
                      {designationOptions.map(option => (
                        <option key={option} value={option}>{option}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Joining Date</label>
                    <input
                      type="date"
                      name="joiningDate"
                      value={formData.joiningDate}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border rounded-md"
                      required
                    />
                  </div>
                </div>

                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    type="button"
                    onClick={() => setIsEditModalOpen(false)}
                    className="px-4 py-2 border rounded-md text-gray-700 hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
                    disabled={loading}
                  >
                    {loading ? 'Updating...' : 'Update Employee'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Employee Management UI */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
        <h2 className="text-xl font-semibold">Employee Management</h2>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 w-full sm:w-auto"
        >
          Add New Employee
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-40">
          <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
        </div>
      ) : employees.length === 0 ? (
        <div className="bg-gray-50 rounded-lg p-8 text-center">
          <p className="text-gray-500 text-lg">No employees found</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Email</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Department</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Designation</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Joining Date</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
        {filteredEmployees.map(employee => (
          <tr key={employee._id}>
            <td className="px-6 py-4 whitespace-nowrap">{employee.name}</td>
            <td className="px-6 py-4 whitespace-nowrap">{employee.email}</td>
            <td className="px-6 py-4 whitespace-nowrap">{employee.department || 'N/A'}</td>
            <td className="px-6 py-4 whitespace-nowrap">{employee.designation}</td>
            <td className="px-6 py-4 whitespace-nowrap">
              {employee.joiningDate ? new Date(employee.joiningDate).toLocaleDateString() : 'N/A'}
            </td>
            <td className="px-6 py-4 whitespace-nowrap flex gap-2">
              <button 
                onClick={() => handleEditEmployee(employee)}
                className="text-blue-600 hover:text-blue-800"
              >
                Edit
              </button>
              <button 
                onClick={() => handleDeleteEmployee(employee._id)}
                className="text-red-600 hover:text-red-800"
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
          </table>
        </div>
      )}
    </div>
  );
};


const StatCard = ({ title, value, icon }) => (
  <div className="bg-white p-4 rounded-lg border border-gray-200 flex items-center">
    <div className="p-3 rounded-full bg-gray-100 mr-4">
      {icon}
    </div>
    <div>
      <p className="text-sm text-gray-500">{title}</p>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  </div>
);



export default HRDashboard; 