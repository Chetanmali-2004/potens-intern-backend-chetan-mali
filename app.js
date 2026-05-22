const express = require('express');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

let logsTable = [];
const API_KEY = "potens_secret_token_2026";

const auth = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

function calculateHash(actor, action, payload, prevHash) {
  const dataString = `${actor}${action}${JSON.stringify(payload)}${prevHash}`;
  return crypto.createHash('sha256').update(dataString).digest('hex');
}

app.post('/log', auth, (req, res) => {
  const { actor, action, payload } = req.body;
  if (!actor || !action || !payload) {
    return res.status(400).json({ error: 'Missing fields' });
  }
  const prevHash = logsTable.length > 0 ? logsTable[logsTable.length - 1].current_hash : '0';
  const currentHash = calculateHash(actor, action, payload, prevHash);
  const newLog = {
    id: logsTable.length + 1,
    actor,
    action,
    payload,
    prev_hash: prevHash,
    current_hash: currentHash,
    timestamp: new Date().toISOString()
  };
  logsTable.push(newLog);
  res.status(201).json(newLog);
});

app.get('/log/:id', auth, (req, res) => {
  const log = logsTable.find(l => l.id === parseInt(req.params.id));
  if (!log) return res.status(404).json({ error: 'Not found' });
  const recomputedHash = calculateHash(log.actor, log.action, log.payload, log.prev_hash);
  res.json({ entry: log, verified: recomputedHash === log.current_hash });
});

app.get('/verify', auth, (req, res) => {
  let expectedPrevHash = '0';
  for (let i = 0; i < logsTable.length; i++) {
    const row = logsTable[i];
    if (row.prev_hash !== expectedPrevHash) {
      return res.json({ status: 'fail', first_broken_id: row.id });
    }
    const currentCalculated = calculateHash(row.actor, row.action, row.payload, row.prev_hash);
    if (row.current_hash !== currentCalculated) {
      return res.json({ status: 'fail', first_broken_id: row.id });
    }
    expectedPrevHash = row.current_hash;
  }
  res.json({ status: 'pass', message: 'Chain is integral.' });
});

app.get('/export', auth, (req, res) => {
  res.json({ count: logsTable.length, data: logsTable });
});

app.get('/', (req, res) => res.json({ message: 'Log Service API Running.' }));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
