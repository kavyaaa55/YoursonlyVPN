// src/api/vpnApi.js
import axios from 'axios';

const BASE = 'http://localhost:8000';

export const classifyRequest = async (data) => {
  const res = await axios.post(`${BASE}/classify`, data);
  return res.data;
};

export const getProfiles = async () => {
  const res = await axios.get(`${BASE}/profiles`);
  return res.data;
};

// WebSocket connection for live feed
export const createWebSocket = (onMessage) => {
  const ws = new WebSocket('ws://localhost:8000/ws');
  ws.onmessage = (e) => onMessage(JSON.parse(e.data));
  return ws;
};
