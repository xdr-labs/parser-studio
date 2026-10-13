import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles.css';
import './guided/guided.css';
import './guided/auto.css';
import './guided/twoPath.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
