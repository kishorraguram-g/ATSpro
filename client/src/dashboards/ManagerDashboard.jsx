import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Box,
  Typography,
  Container,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Paper,
  CircularProgress,
  TableContainer,
  Chip,
  Button,
  AppBar,
  Toolbar,
  IconButton,
  Snackbar,
  Alert
} from '@mui/material';
import { Logout as LogoutIcon } from '@mui/icons-material';
import dayjs from 'dayjs';

const AttendanceSummary = () => {
  const navigate = useNavigate();
  const [attendanceData, setAttendanceData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Status color mapping
  const statusColors = {
    Present: 'success',
    Absent: 'error',
    Late: 'warning',
    'Half Day': 'info'
  };

  // Fetch attendance data
  const fetchAttendanceData = async () => {
    try {
      setLoading(true);
      const employeeId = localStorage.getItem('employeeId');
      const token = localStorage.getItem('token');
      const response = await axios.get(
        `http://localhost:4000/attendance/team-summary/${employeeId}`,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      );

      if (response.data.status === 'success' && response.data.data) {
        setAttendanceData(response.data.data);
      }
    } catch (error) {
      console.error('Error fetching attendance data:', error);
      setSnackbar({ open: true, message: 'Failed to fetch attendance data', severity: 'error' });
    } finally {
      setLoading(false);
    }
  };

  // Handle logout
  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('employeeId');
    navigate('/'); // Redirect to login page
  };

  // Close snackbar
  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  // Initial data fetch
  useEffect(() => {
    fetchAttendanceData();
  }, []);

  return (
    <>
      <AppBar position="static">
        <Toolbar>
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            Attendance System
          </Typography>
          <IconButton color="inherit" onClick={handleLogout}>
            <LogoutIcon />
          </IconButton>
        </Toolbar>
      </AppBar>

      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom>
            Attendance Summary
          </Typography>
          
          <Card elevation={3}>
            <CardContent>
              <Box sx={{ 
                display: 'flex', 
                justifyContent: 'space-between', 
                alignItems: 'center', 
                mb: 3 
              }}>
                <Typography variant="h6" component="h2">
                  Team Attendance Records
                </Typography>
                <Button 
                  variant="contained" 
                  onClick={fetchAttendanceData}
                  disabled={loading}
                >
                  {loading ? <CircularProgress size={24} /> : 'Refresh'}
                </Button>
              </Box>
              
              {loading ? (
                <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                  <CircularProgress />
                </Box>
              ) : (
                <TableContainer component={Paper}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell>Employee</TableCell>
                        <TableCell>Date</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Type</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {attendanceData.length > 0 ? (
                        attendanceData.map((record) => (
                          <TableRow key={record._id} hover>
                            <TableCell>{record.employee?.name || 'N/A'}</TableCell>
                            <TableCell>{dayjs(record.date).format('MMM D, YYYY')}</TableCell>
                            <TableCell>
                              <Chip 
                                label={record.status} 
                                color={statusColors[record.status] || 'default'} 
                                size="small"
                              />
                            </TableCell>
                            <TableCell>{record.attendanceType}</TableCell>
                          </TableRow>
                        ))
                      ) : (
                        <TableRow>
                          <TableCell colSpan={4} align="center">
                            No attendance records found
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Box>
      </Container>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
      >
        <Alert onClose={handleCloseSnackbar} severity={snackbar.severity}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </>
  );
};

export default AttendanceSummary;