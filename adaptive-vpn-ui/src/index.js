import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

// Reset default browser styles
document.body.style.margin = '0';
document.body.style.padding = '0';
document.body.style.background = '#0D1117';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
