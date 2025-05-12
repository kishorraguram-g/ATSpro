import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import { FiLogOut, FiUser, FiCalendar, FiX, FiCheck, FiXCircle, FiClock, FiHome, FiActivity } from 'react-icons/fi';

const EmployeeDashboard = () => {
  const [attendanceSummary, setAttendanceSummary] = useState([]);
  const [filteredRecords, setFilteredRecords] = useState([]);
  const [selectedDate, setSelectedDate] = useState('');
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({
    present: 0,
    absent: 0,
    onLeave: 0,
    remote: 0
  });
  const [typeStats, setTypeStats] = useState({
    regular: 0,
    remote: 0,
    sickLeave: 0,
    other: 0
  });
  const navigate = useNavigate();

  // Calculate statistics from attendance data
  const calculateStats = (data) => {
    const statusCounts = {
      present: data.filter(r => r.status === 'Present').length,
      absent: data.filter(r => r.status === 'Absent').length,
      onLeave: data.filter(r => r.status === 'On Leave').length,
      remote: data.filter(r => r.status === 'Remote').length
    };

    const typeCounts = {
      regular: data.filter(r => r.attendanceType === 'Regular').length,
      remote: data.filter(r => r.attendanceType === 'Remote').length,
      sickLeave: data.filter(r => r.attendanceType === 'Sick Leave').length,
      other: data.filter(r => r.attendanceType === 'Other').length
    };

    setStats(statusCounts);
    setTypeStats(typeCounts);
  };

  // Fetch attendance summary
  useEffect(() => {
    const fetchAttendanceSummary = async () => {
      try {
        setLoading(true);
        const employeeId = localStorage.getItem('employeeId')?.replace(/"/g, '');
        const token = localStorage.getItem('token');

        if (!employeeId || !token) {
          toast.error('Missing credentials');
          return;
        }

        const response = await axios.get(`http://localhost:4000/attendance/me/${employeeId}`, {
          headers: {
            Authorization: `Bearer ${token}`
          }
        });
        console.log(response.data.data[0].team)
        
        setAttendanceSummary(response.data.data);
        setFilteredRecords(response.data.data);
        calculateStats(response.data.data);
      } catch (error) {
        toast.error('Failed to fetch attendance summary');
        console.error(error);
      } finally {
        setLoading(false);
      }
    };

    fetchAttendanceSummary();
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('employeeId');
    toast.success('Logged out successfully');
    navigate('/');
  };

  const handleDateChange = (e) => {
    const date = e.target.value;
    setSelectedDate(date);
    
    if (!date) {
      setFilteredRecords(attendanceSummary);
      calculateStats(attendanceSummary);
      return;
    }

    const filtered = attendanceSummary.filter(record => {
      const recordDate = new Date(record.date).toISOString().split('T')[0];
      return recordDate === date;
    });

    setFilteredRecords(filtered);
    calculateStats(filtered);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'Present':
        return <FiCheck className="text-green-500" />;
      case 'Absent':
        return <FiXCircle className="text-red-500" />;
      case 'On Leave':
        return <FiActivity className="text-purple-500" />;
      case 'Remote':
        return <FiHome className="text-blue-500" />;
      default:
        return <FiClock className="text-yellow-500" />;
    }
  };

  const getTypeBadge = (type) => {
    let colorClasses = '';
    switch (type) {
      case 'Regular':
        colorClasses = 'bg-green-100 text-green-800';
        break;
      case 'Remote':
        colorClasses = 'bg-blue-100 text-blue-800';
        break;
      case 'Sick Leave':
        colorClasses = 'bg-yellow-100 text-yellow-800';
        break;
      case 'Other':
        colorClasses = 'bg-gray-100 text-gray-800';
        break;
      default:
        colorClasses = 'bg-gray-100 text-gray-800';
    }
    return (
      <span className={`px-2 py-1 text-xs font-semibold rounded-full ${colorClasses}`}>
        {type}
      </span>
    );
  };

  return (
    <div className="min-h-screen bg-gray-50 p-4 md:p-6">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
          <div>
            <h1 className="text-2xl md:text-3xl font-bold text-gray-800">Employee Dashboard</h1>
            <p className="text-gray-600 mt-1">
              {loading ? 'Loading...' : `You have ${attendanceSummary.length} attendance records`}
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            {/* <button
              onClick={() => navigate('/profile')}
              className="flex items-center gap-2 bg-white hover:bg-gray-100 px-4 py-2 rounded-lg transition-colors shadow-sm border border-gray-200"
            >
              <div className="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-white">
                <FiUser size={16} />
              </div>
              <span className="font-medium hidden sm:inline">Profile</span>
            </button> */}
            
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 bg-white hover:bg-red-50 text-red-600 px-4 py-2 rounded-lg transition-colors shadow-sm border border-gray-200"
            >
              <FiLogOut size={16} />
              <span className="font-medium hidden sm:inline">Logout</span>
            </button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {/* Status Cards */}
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-gray-500 font-medium">Present</h3>
              <div className="p-2 rounded-full bg-green-50 text-green-600">
                <FiCheck size={18} />
              </div>
            </div>
            <p className="text-2xl font-bold mt-2">{stats.present}</p>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-gray-500 font-medium">Absent</h3>
              <div className="p-2 rounded-full bg-red-50 text-red-600">
                <FiXCircle size={18} />
              </div>
            </div>
            <p className="text-2xl font-bold mt-2">{stats.absent}</p>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-gray-500 font-medium">On Leave</h3>
              <div className="p-2 rounded-full bg-purple-50 text-purple-600">
                <FiActivity size={18} />
              </div>
            </div>
            <p className="text-2xl font-bold mt-2">{stats.onLeave}</p>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <div className="flex items-center justify-between">
              <h3 className="text-gray-500 font-medium">Remote</h3>
              <div className="p-2 rounded-full bg-blue-50 text-blue-600">
                <FiHome size={18} />
              </div>
            </div>
            <p className="text-2xl font-bold mt-2">{stats.remote}</p>
          </div>
        </div>

        {/* Type Distribution Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-gray-500 font-medium">Regular</h3>
            <p className="text-2xl font-bold mt-2">{typeStats.regular}</p>
            <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
              <div 
                className="bg-green-500 h-2 rounded-full" 
                style={{ width: `${(typeStats.regular / attendanceSummary.length) * 100 || 0}%` }}
              ></div>
            </div>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-gray-500 font-medium">Remote</h3>
            <p className="text-2xl font-bold mt-2">{typeStats.remote}</p>
            <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
              <div 
                className="bg-blue-500 h-2 rounded-full" 
                style={{ width: `${(typeStats.remote / attendanceSummary.length) * 100 || 0}%` }}
              ></div>
            </div>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-gray-500 font-medium">Sick Leave</h3>
            <p className="text-2xl font-bold mt-2">{typeStats.sickLeave}</p>
            <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
              <div 
                className="bg-yellow-500 h-2 rounded-full" 
                style={{ width: `${(typeStats.sickLeave / attendanceSummary.length) * 100 || 0}%` }}
              ></div>
            </div>
          </div>
          
          <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
            <h3 className="text-gray-500 font-medium">Other</h3>
            <p className="text-2xl font-bold mt-2">{typeStats.other}</p>
            <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
              <div 
                className="bg-gray-500 h-2 rounded-full" 
                style={{ width: `${(typeStats.other / attendanceSummary.length) * 100 || 0}%` }}
              ></div>
            </div>
          </div>
        </div>

        {/* Filter Section */}
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200 mb-6">
          <h2 className="text-lg font-semibold text-gray-800 mb-4 flex items-center gap-2">
            <FiCalendar /> Filter Records
          </h2>
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
            <div className="relative flex-1 w-full">
              <label className="block text-sm font-medium text-gray-700 mb-1">Select Date</label>
              <input
                type="date"
                value={selectedDate}
                onChange={handleDateChange}
                className="w-full p-2 border border-gray-300 rounded-md focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
            
            {selectedDate && (
              <button
                onClick={() => {
                  setSelectedDate('');
                  setFilteredRecords(attendanceSummary);
                  calculateStats(attendanceSummary);
                }}
                className="flex items-center gap-1 text-sm text-gray-600 hover:text-gray-800 mt-6 sm:mt-5"
              >
                <FiX size={14} /> Clear filter
              </button>
            )}
          </div>
        </div>

        {/* Attendance Records */}
        <div className="bg-white p-4 rounded-lg shadow-sm border border-gray-200">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-4">
            <h2 className="text-lg font-semibold text-gray-800 flex items-center gap-2">
              <FiClock /> Attendance Records
            </h2>
            <p className="text-sm text-gray-500 mt-1 sm:mt-0">
              Showing {filteredRecords.length} record{filteredRecords.length !== 1 ? 's' : ''}
            </p>
          </div>
          
          {loading ? (
            <div className="flex justify-center items-center h-40">
              <div className="animate-spin rounded-full h-10 w-10 border-t-2 border-b-2 border-blue-500"></div>
            </div>
          ) : filteredRecords.length === 0 ? (
            <div className="bg-gray-50 p-8 rounded-lg text-center">
              <FiCalendar className="mx-auto text-gray-400 mb-3" size={32} />
              <h3 className="text-gray-600 font-medium">
                {selectedDate ? 'No records found for selected date' : 'No attendance records available'}
              </h3>
              <p className="text-gray-500 text-sm mt-1">
                {!selectedDate && 'Your attendance records will appear here once available'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Team</th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredRecords.map((record) => (
                    <tr key={record._id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-gray-900">
                          {new Date(record.date).toLocaleDateString('en-US', {
                            weekday: 'short',
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric'
                          })}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(record.status)}
                          <span className={`text-sm font-medium ${
                            record.status === 'Present' ? 'text-green-600' : 
                            record.status === 'Absent' ? 'text-red-600' : 
                            record.status === 'On Leave' ? 'text-purple-600' :
                            record.status === 'Remote' ? 'text-blue-600' : 'text-gray-600'
                          }`}>
                            {record.status}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        {getTypeBadge(record.attendanceType)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {record.team?.name || 'N/A'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default EmployeeDashboard;