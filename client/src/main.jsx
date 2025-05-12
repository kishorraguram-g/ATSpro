import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
     {/* 👈 This is required for routing */}
      <App />
  </React.StrictMode>
)
