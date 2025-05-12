import React, { useState, useEffect } from 'react';
import { FiPlus, FiX, FiEdit2, FiTrash2, FiCalendar, FiRefreshCw, FiSave,FiLogOut } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom'; 
import axios from 'axios';

const AdminDashboard = () => {
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [userType, setUserType] = useState('');
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [creatingUser, setCreatingUser] = useState(false);
  const [updatingUser, setUpdatingUser] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
    confirmPassword: '',
    department: '',
    joiningDate: new Date().toISOString().split('T')[0]
  });
  const [editingUserId, setEditingUserId] = useState(null);
  const [editFormData, setEditFormData] = useState({
    name: '',
    email: '',
    department: '',
    designation: '',
    joiningDate: ''
  });

  const departmentOptions = [
    { value: 'IT', label: 'IT' },
    { value: 'HR', label: 'HR' },
    { value: 'Technical Support', label: 'Technical Support' },
    { value: 'Admin', label: 'Admin' }
  ];

  const designationOptions = [
    { value: 'HR', label: 'HR' },
    { value: 'Manager', label: 'Manager' },
    { value: 'Employee', label: 'Employee' },
    { value: 'Developer', label: 'Developer' },
    { value: 'QA', label: 'Quality Assurance' }
  ];

  const fetchUsers = async (forceReload = false) => {
    try {
      if (forceReload) {
        setRefreshing(true);
        setUsers([]);
      } else {
        setLoading(true);
      }

      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await axios.get('http://localhost:4000/employees', {
        headers: {
          Authorization: `Bearer ${token}`,
          'Cache-Control': 'no-cache'
        }
      });

      const usersData = Array.isArray(response.data?.data) ? response.data.data :
                       Array.isArray(response.data?.users) ? response.data.users :
                       [];
      
      setUsers(usersData);
      setError('');
    } catch (error) {
      console.error('Error fetching users:', error);
      setError(error.response?.data?.message || error.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleEditInputChange = (e) => {
    const { name, value } = e.target;
    setEditFormData(prev => ({ ...prev, [name]: value }));
  };

  const validateForm = () => {
    if (formData.password !== formData.confirmPassword) {
      setError("Passwords don't match");
      return false;
    }
    if (!formData.name || !formData.email || !formData.password || 
        !formData.department || !formData.joiningDate) {
      setError("All fields are required");
      return false;
    }
    setError('');
    return true;
  };

  const validateEditForm = () => {
    if (!editFormData.name || !editFormData.email || 
        !editFormData.department || !editFormData.joiningDate) {
      setError("All fields are required");
      return false;
    }
    setError('');
    return true;
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setCreatingUser(true);
    try {
      const userData = {
        name: formData.name,
        email: formData.email,
        password: formData.password,
        confirmPassword: formData.confirmPassword,
        department: formData.department,
        designation: userType,
        joiningDate: formData.joiningDate
      };

      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No authentication token found');
      }

      await axios.post(
        'http://localhost:4000/employees/create',
        userData,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );
      
      await fetchUsers(true);
      
      setFormData({ 
        name: '', 
        email: '', 
        password: '', 
        confirmPassword: '',
        department: '',
        joiningDate: new Date().toISOString().split('T')[0]
      });
      setShowCreateUser(false);
    } catch (error) {
      console.error('Error creating user:', error);
      setError(error.response?.data?.message || error.message || "Failed to create user");
    } finally {
      setCreatingUser(false);
    }
  };

  const handleEditUser = (userId) => {
    const userToEdit = users.find(user => user._id === userId);
    if (!userToEdit) return;

    setEditFormData({
      name: userToEdit.name,
      email: userToEdit.email,
      department: userToEdit.department,
      designation: userToEdit.designation,
      joiningDate: userToEdit.joiningDate ? 
        new Date(userToEdit.joiningDate).toISOString().split('T')[0] : 
        new Date().toISOString().split('T')[0]
    });
    setEditingUserId(userId);
  };

  const handleUpdateUser = async (e) => {
    e.preventDefault();
    if (!validateEditForm()) return;

    setUpdatingUser(true);
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('No authentication token found');
      }

      const response = await axios.patch(
        `http://localhost:4000/employees/employees/${editingUserId}`,
        editFormData,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      setUsers(users.map(user => 
        user._id === editingUserId ? response.data.data.user : user
      ));
      setEditingUserId(null);
      setError('');
    } catch (error) {
      console.error('Error updating user:', error);
      setError(error.response?.data?.message || error.message || "Failed to update user");
    } finally {
      setUpdatingUser(false);
    }
  };
  const handleLogout = () => {
    // Remove token and designation from localStorage
    localStorage.removeItem('token');
    localStorage.removeItem('designation');
    
    // Redirect to login page
    window.location.href = '/'; // Make sure this matches your login route
  };

  const handleDelete = async (userId) => {
    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        const token = localStorage.getItem('token');
        if (!token) {
          throw new Error('No authentication token found');
        }

        await axios.delete(`http://localhost:4000/employees/employees/${userId}`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        
        setUsers(prevUsers => prevUsers.filter(user => user._id !== userId));
        await fetchUsers(true);
      } catch (error) {
        console.error('Error deleting user:', error);
        setError(error.response?.data?.message || error.message || "Failed to delete user");
      }
    }
  };

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-6">Admin Dashboard</h1>
      <div className="absolute top-6 right-6">
        <button
          onClick={handleLogout}
          className="flex items-cent bg-red-500 hover:bg-red-600 text-white py-2 px-4 rounded-lg"
        >
          <FiLogOut className="mr-2" />
          Logout
        </button>
        
      </div>
      {error && !showCreateUser && !editingUserId && (
        <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md">
          {error}
          <button 
            onClick={() => setError('')}
            className="float-right font-bold"
          >
            ×
          </button>
        </div>
      )}
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <button 
          onClick={() => {
            setUserType('HR');
            setShowCreateUser(true);
            setError('');
          }}
          className="bg-blue-600 hover:bg-blue-700 text-white py-3 px-6 rounded-lg flex items-center"
        >
          <FiPlus className="mr-2" /> Create HR
        </button>
        
        <button 
          onClick={() => {
            setUserType('Manager');
            setShowCreateUser(true);
            setError('');
          }}
          className="bg-green-600 hover:bg-green-700 text-white py-3 px-6 rounded-lg flex items-center"
        >
          <FiPlus className="mr-2" /> Create Manager
        </button>

        <button
          onClick={() => fetchUsers(true)}
          disabled={refreshing}
          className="bg-gray-600 hover:bg-gray-700 text-white py-3 px-6 rounded-lg flex items-center"
        >
          {refreshing ? (
            <FiRefreshCw className="mr-2 animate-spin" />
          ) : (
            <FiRefreshCw className="mr-2" />
          )}
          Refresh Users
        </button>
      </div>

      {/* Create User Modal */}
      {showCreateUser && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-semibold">
                Create New {userType}
              </h2>
              <button 
                onClick={() => {
                  setShowCreateUser(false);
                  setError('');
                }}
                className="text-gray-500 hover:text-gray-700"
              >
                <FiX size={24} />
              </button>
            </div>

            {error && (
              <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md">
                {error}
                <button 
                  onClick={() => setError('')}
                  className="float-right font-bold"
                >
                  ×
                </button>
              </div>
            )}

            <form onSubmit={handleCreateUser} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Full Name *
                </label>
                <input
                  type="text"
                  name="name"
                  value={formData.name}
                  onChange={handleInputChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  required
                  placeholder="Enter full name"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email *
                </label>
                <input
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleInputChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  required
                  placeholder="Enter email address"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Password *
                  </label>
                  <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                    minLength="6"
                    placeholder="Enter password"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Confirm Password *
                  </label>
                  <input
                    type="password"
                    name="confirmPassword"
                    value={formData.confirmPassword}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                    minLength="6"
                    placeholder="Confirm password"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Department *
                  </label>
                  <select
                    name="department"
                    value={formData.department}
                    onChange={handleInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  >
                    <option value="">Select Department</option>
                    {departmentOptions.map(dept => (
                      <option key={dept.value} value={dept.value}>
                        {dept.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Joining Date *
                  </label>
                  <div className="relative">
                    <input
                      type="date"
                      name="joiningDate"
                      value={formData.joiningDate}
                      onChange={handleInputChange}
                      className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 pl-10"
                      required
                    />
                    <FiCalendar className="absolute left-3 top-3 text-gray-400" />
                  </div>
                </div>
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={creatingUser}
                  className={`w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md ${
                    creatingUser ? 'opacity-70 cursor-not-allowed' : ''
                  }`}
                >
                  {creatingUser ? (
                    <span className="flex items-center justify-center">
                      <FiRefreshCw className="animate-spin mr-2" />
                      Creating...
                    </span>
                  ) : (
                    'Create User'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit User Modal */}
      {editingUserId && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-semibold">
                Edit User
              </h2>
              <button 
                onClick={() => {
                  setEditingUserId(null);
                  setError('');
                }}
                className="text-gray-500 hover:text-gray-700"
              >
                <FiX size={24} />
              </button>
            </div>

            {error && (
              <div className="mb-4 p-3 bg-red-100 text-red-700 rounded-md">
                {error}
                <button 
                  onClick={() => setError('')}
                  className="float-right font-bold"
                >
                  ×
                </button>
              </div>
            )}

            <form onSubmit={handleUpdateUser} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Full Name *
                </label>
                <input
                  type="text"
                  name="name"
                  value={editFormData.name}
                  onChange={handleEditInputChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  required
                  placeholder="Enter full name"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email *
                </label>
                <input
                  type="email"
                  name="email"
                  value={editFormData.email}
                  onChange={handleEditInputChange}
                  className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                  required
                  placeholder="Enter email address"
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Department *
                  </label>
                  <select
                    name="department"
                    value={editFormData.department}
                    onChange={handleEditInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  >
                    <option value="">Select Department</option>
                    {departmentOptions.map(dept => (
                      <option key={dept.value} value={dept.value}>
                        {dept.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Role *
                  </label>
                  <select
                    name="designation"
                    value={editFormData.designation}
                    onChange={handleEditInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
                    required
                  >
                    <option value="">Select Role</option>
                    {designationOptions.map(role => (
                      <option key={role.value} value={role.value}>
                        {role.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Joining Date *
                </label>
                <div className="relative">
                  <input
                    type="date"
                    name="joiningDate"
                    value={editFormData.joiningDate}
                    onChange={handleEditInputChange}
                    className="w-full px-4 py-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500 pl-10"
                    required
                  />
                  <FiCalendar className="absolute left-3 top-3 text-gray-400" />
                </div>
              </div>

              <div className="pt-4">
                <button
                  type="submit"
                  disabled={updatingUser}
                  className={`w-full bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded-md ${
                    updatingUser ? 'opacity-70 cursor-not-allowed' : ''
                  }`}
                >
                  {updatingUser ? (
                    <span className="flex items-center justify-center">
                      <FiRefreshCw className="animate-spin mr-2" />
                      Updating...
                    </span>
                  ) : (
                    <span className="flex items-center justify-center">
                      <FiSave className="mr-2" />
                      Update User
                    </span>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Users list section */}
      <div className="mt-8">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-semibold">User Management</h2>
          <div className="text-sm text-gray-500">
            {users.length} user(s) found
          </div>
        </div>
        
        {loading ? (
          <div className="flex justify-center items-center h-32">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
          </div>
        ) : users.length === 0 ? (
          <div className="text-center py-8">
            <p className="text-gray-600 mb-4">No users found</p>
            <button
              onClick={() => fetchUsers(true)}
              className="px-4 py-2 bg-blue-500 text-white rounded"
            >
              Refresh Data
            </button>
          </div>
        ) : (
          <div className="bg-white shadow rounded-lg overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Department</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Joining Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
  {users.map((user) => (
    <tr key={user._id}>
      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user.name}</td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user.email}</td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        {user.department || 'N/A'}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 capitalize">
        {user.designation || 'N/A'}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        {user.joiningDate ? new Date(user.joiningDate).toLocaleDateString() : 'N/A'}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
        {user.designation !== "Admin" && (  // Only show buttons if NOT Admin
          <>
            <button 
              onClick={() => handleEditUser(user._id)}
              className="text-blue-600 hover:text-blue-900 mr-4"
            >
              <FiEdit2 />
            </button>
            <button 
              onClick={() => handleDelete(user._id)}
              className="text-red-600 hover:text-red-900"
            >
              <FiTrash2 />
            </button>
          </>
        )}
      </td>
    </tr>
  ))}
</tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminDashboard;