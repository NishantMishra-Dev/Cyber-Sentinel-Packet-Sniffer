import React, { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

function App() {
  const [packets, setPackets] = useState([]);
  const [isSniffing, setIsSniffing] = useState(true);

  // Fetch live network packets from the Python backend API
  const fetchLivePackets = () => {
    fetch('http://127.0.0.1:5000/api/packets')
      .then((response) => response.json())
      .then((data) => setPackets(data))
      .catch((error) => console.error("Error connecting to API: ", error));
  };

  // Poll the API every 2 seconds for fresh data
  useEffect(() => {
    fetchLivePackets();
    const interval = setInterval(fetchLivePackets, 2000);
    return () => clearInterval(interval);
  }, []);

  // Handle Pause/Resume functionality
  const handleToggle = () => {
    fetch('http://127.0.0.1:5000/api/toggle', { method: 'POST' })
      .then(res => res.json())
      .then(data => setIsSniffing(data.is_sniffing))
      .catch(err => console.error(err));
  };

  // Handle Clear Data functionality
  const handleClear = () => {
    fetch('http://127.0.0.1:5000/api/clear', { method: 'POST' })
      .then(() => setPackets([]))
      .catch(err => console.error(err));
  };

  // Calculate protocol distribution for the Pie Chart
  const protocolCounts = packets.reduce((acc, packet) => {
    acc[packet.protocol] = (acc[packet.protocol] || 0) + 1;
    return acc;
  }, {});

  const chartData = Object.keys(protocolCounts).map(key => ({
    name: key,
    value: protocolCounts[key]
  }));

  const COLORS = ['#00d2ff', '#e94560', '#f39c12', '#2ecc71'];

  return (
    <div style={{ padding: '30px', fontFamily: 'Arial, sans-serif', backgroundColor: '#1a1a2e', minHeight: '100vh', color: '#e0e0e0' }}>
      <h1 style={{ color: '#00d2ff', textAlign: 'center' }}>🛡️ Cyber-Sentinel: Advanced Sniffer</h1>
      <p style={{ color: '#a0a0a0', textAlign: 'center', marginBottom: '20px' }}>Real-time Traffic, Threat Detection, Geo-Location & Domain Resolution</p>

      {/* CONTROLS SECTION */}
      <div style={{ display: 'flex', justifyContent: 'center', gap: '20px', marginBottom: '30px' }}>
        <button 
          onClick={handleToggle} 
          style={{
            padding: '10px 25px', 
            fontSize: '16px', 
            fontWeight: 'bold', 
            color: 'white', 
            backgroundColor: isSniffing ? '#e74c3c' : '#2ecc71', 
            border: 'none', 
            borderRadius: '5px', 
            cursor: 'pointer',
            boxShadow: '0 4px 6px rgba(0,0,0,0.3)'
          }}>
          {isSniffing ? '⏸ Stop Sniffing' : '▶ Start Sniffing'}
        </button>
        <button 
          onClick={handleClear} 
          style={{
            padding: '10px 25px', 
            fontSize: '16px', 
            fontWeight: 'bold', 
            color: 'white', 
            backgroundColor: '#34495e', 
            border: 'none', 
            borderRadius: '5px', 
            cursor: 'pointer',
            boxShadow: '0 4px 6px rgba(0,0,0,0.3)'
          }}>
          🗑 Clear Data
        </button>
      </div>

      {/* CHART SECTION */}
      <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '20px' }}>
        <div style={{ backgroundColor: '#16213e', padding: '20px', borderRadius: '8px', boxShadow: '0 4px 15px rgba(0,0,0,0.5)', width: '400px', height: '300px' }}>
          <h3 style={{ textAlign: 'center', color: '#fff', marginTop: 0 }}>Live Protocol Distribution</h3>
          {chartData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={chartData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#1a1a2e', border: '1px solid #00d2ff' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <p style={{ textAlign: 'center', color: '#7f8c8d', marginTop: '80px' }}>Waiting for data...</p>
          )}
        </div>
      </div>

      {/* TABLE SECTION */}
      <div style={{ backgroundColor: '#16213e', padding: '20px', borderRadius: '8px', boxShadow: '0 4px 15px rgba(0,0,0,0.5)', overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', minWidth: '900px' }}>
          <thead>
            <tr style={{ backgroundColor: '#0f3460', color: 'white' }}>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>No.</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>Time</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>Source IP</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>Destination IP</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a', color: '#a29bfe' }}>Host / Domain</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>Location</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>Protocol</th>
              <th style={{ padding: '12px', borderBottom: '2px solid #2a2a4a' }}>Status</th>
            </tr>
          </thead>
          <tbody>
            {packets.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ padding: '12px', textAlign: 'center', color: '#7f8c8d' }}>
                  {isSniffing ? 'Listening for network packets...' : 'Sniffer is paused.'}
                </td>
              </tr>
            ) : (
              packets.map((packet) => (
                <tr 
                  key={packet.id} 
                  style={{ 
                    backgroundColor: packet.is_threat ? '#4a0000' : 'transparent',
                    borderBottom: '1px solid #2a2a4a',
                    transition: 'background-color 0.3s'
                  }}
                >
                  <td style={{ padding: '12px' }}>{packet.id}</td>
                  <td style={{ padding: '12px' }}>{packet.time}</td>
                  <td style={{ padding: '12px', color: '#e94560', fontWeight: 'bold' }}>{packet.src}</td>
                  <td style={{ padding: '12px', color: '#00d2ff', fontWeight: 'bold' }}>{packet.dst}</td>
                  <td style={{ padding: '12px', color: '#a29bfe', fontSize: '0.9em' }}>{packet.domain}</td>
                  <td style={{ padding: '12px', color: '#f39c12' }}>{packet.location}</td>
                  <td style={{ padding: '12px', color: '#ffd700' }}>{packet.protocol}</td>
                  <td style={{ padding: '12px', fontWeight: 'bold', color: packet.is_threat ? '#ff4d4d' : '#2ecc71' }}>
                    {packet.is_threat ? '⚠️ High Traffic' : '✅ Normal'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;