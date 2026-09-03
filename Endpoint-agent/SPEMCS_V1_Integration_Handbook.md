# SPEMCS Endpoint Agent V1 — Integration & Operations Handbook

This document is a comprehensive handbook for operating, testing, and integrating the **SPEMCS V1 Endpoint Agent** with central Backend APIs, Web Frontend exam portals, and Machine Learning (ML) proctoring pipelines.

---

## 1. Operational Testing & Commands

### Prerequisites
- Windows 10 / 11 PC
- .NET 8.0 SDK installed

### Running the System Locally

#### Terminal 1: Agent Worker Service Host
```powershell
$env:PATH = "C:\Users\shrma\AppData\Local\Microsoft\dotnet;$env:PATH"
$env:SPEMCS_AGENT_UI_PATH = "c:\Users\shrma\Downloads\k\spemcs\endpoint-agent\src\Spemcs.Agent.UI\bin\Debug\net8.0-windows\Spemcs.Agent.UI.exe"

dotnet run --project c:\Users\shrma\Downloads\k\spemcs\endpoint-agent\src\Spemcs.Agent.Service
```

#### Terminal 2: Service Control & Inspection Harness
```powershell
$env:PATH = "C:\Users\shrma\AppData\Local\Microsoft\dotnet;$env:PATH"

dotnet run --project c:\Users\shrma\Downloads\k\spemcs\endpoint-agent\src\Spemcs.Agent.TestHarness -- --service
```

#### Interactive Verification Commands:
- Type `start` in Terminal 2:
  - WPF window launches **immediately** with a progress loading indicator ("Scanning running processes for examination compliance...").
  - Results update smoothly to display clean status or list unapproved running applications.
  - Candidate clicks `[ Continue ]`.
  - WPF window transitions to **SPEMCS Student Verification** requesting candidate Roll Number.
  - Candidate enters Roll Number (e.g. `STU-10023` or `2301921540174`) and clicks `Begin Examination`.
  - Blocking UI exits cleanly. Continuous monitoring starts silently.
- Open Notepad or Edge mid-exam:
  - No popups or terminations occur (candidate exam flow is uninterrupted).
  - Type `events` in Terminal 2 to inspect recorded `APPLICATION_OPENED` / `APPLICATION_CLOSED` violation events!

---

## 2. API Contract Specifications

### Central Backend REST Endpoints

#### A. Device Registration (`POST /api/v1/devices/register`)
- **Request**:
  ```json
  {
    "deviceName": "LAB-PC-104",
    "ipAddress": "192.168.1.50"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "deviceId": "9b1deb4d-3b7d-4b69-9171-705641b2bd7b",
    "deviceName": "LAB-PC-104",
    "ipAddress": "192.168.1.50",
    "registeredAtUtc": "2026-08-14T15:45:00Z"
  }
  ```

#### B. Start Exam Session (`POST /api/v1/sessions/start`)
- **Request**:
  ```json
  {
    "sessionId": "ses_8f9a2b1c3d",
    "approvedBrowser": "Chrome"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "status": "SessionStarted",
    "sessionId": "ses_8f9a2b1c3d"
  }
  ```

#### C. Student Verification (`POST /api/v1/sessions/verify-student`)
- **Request**:
  ```json
  {
    "sessionId": "ses_8f9a2b1c3d",
    "rollNumber": "2301921540174"
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "valid": true,
    "studentName": "John Doe",
    "message": "Verification successful"
  }
  ```

#### D. Security Violation Events (`POST /api/v1/events`)
- **Request**:
  ```json
  {
    "eventId": "e93f1a2b-8c4d-4e5f-9a0b-1c2d3e4f5a6b",
    "deviceName": "LAB-PC-104",
    "studentRollNumber": "2301921540174",
    "eventType": "APPLICATION_OPENED",
    "processId": 14208,
    "processName": "notepad.exe",
    "timestampUtc": "2026-08-14T15:46:10Z",
    "executablePath": "C:\\Windows\\System32\\notepad.exe",
    "reason": "Application outside approved environment (notepad.exe)"
  }
  ```

---

## 3. Central Backend Implementation Examples

### Option A: Node.js (Express & WebSockets)

```javascript
const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const devices = new Map();
const sessions = new Map();
const activeEvents = [];

app.post('/api/v1/devices/register', (req, res) => {
  const { deviceName, ipAddress } = req.body;
  const deviceId = `dev_${Math.random().toString(36).substring(2, 9)}`;
  const device = { deviceId, deviceName, ipAddress, registeredAtUtc: new Date().toISOString() };
  devices.set(deviceId, device);
  res.json(device);
});

app.post('/api/v1/sessions/start', (req, res) => {
  const { sessionId, approvedBrowser } = req.body;
  sessions.set(sessionId, { sessionId, approvedBrowser, status: 'PreCompliance' });
  res.json({ status: 'SessionStarted', sessionId });
});

app.post('/api/v1/sessions/verify-student', (req, res) => {
  const { sessionId, rollNumber } = req.body;
  const session = sessions.get(sessionId) || {};
  session.studentRollNumber = rollNumber;
  session.status = 'Monitoring';
  sessions.set(sessionId, session);
  res.json({ valid: true, message: 'Verification successful' });
});

app.post('/api/v1/events', (req, res) => {
  const event = req.body;
  activeEvents.push(event);

  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'VIOLATION_ALERT', payload: event }));
    }
  });

  res.status(200).json({ status: 'Ingested' });
});

app.get('/api/v1/sessions/:sessionId/status', (req, res) => {
  const session = sessions.get(req.params.sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });
  res.json(session);
});

server.listen(4000, () => console.log('SPEMCS Central Backend running on port 4000'));
```

### Option B: Python (FastAPI & WebSockets)

```python
from fastapi import FastAPI, WebSocket
from pydantic import BaseModel
from typing import Optional
import datetime, uuid

app = FastAPI(title="SPEMCS Central Backend API")

class DeviceRegisterReq(BaseModel):
    deviceName: str
    ipAddress: str

class StudentVerifyReq(BaseModel):
    sessionId: str
    rollNumber: str

class ViolationEventReq(BaseModel):
    eventId: str
    deviceName: str
    studentRollNumber: Optional[str]
    eventType: str
    processId: int
    processName: str
    timestampUtc: str
    executablePath: Optional[str]
    reason: Optional[str]

@app.post("/api/v1/devices/register")
async def register_device(req: DeviceRegisterReq):
    return {
        "deviceId": str(uuid.uuid4()),
        "deviceName": req.deviceName,
        "ipAddress": req.ipAddress,
        "registeredAtUtc": datetime.datetime.utcnow().isoformat()
    }

@app.post("/api/v1/sessions/verify-student")
async def verify_student(req: StudentVerifyReq):
    return {"valid": True, "sessionId": req.sessionId, "rollNumber": req.rollNumber}

@app.post("/api/v1/events")
async def receive_event(event: ViolationEventReq):
    print(f"ALERT: Student {event.studentRollNumber} launched {event.processName} (PID {event.processId})")
    return {"status": "Ingested"}
```

---

## 4. React / Next.js Web Frontend Integration

```tsx
import React, { useState, useEffect } from 'react';

export default function CandidateExamPortal({ sessionId = "ses_8f9a2b1c3d" }) {
  const [sessionStatus, setSessionStatus] = useState('Initializing');
  const [studentRoll, setStudentRoll] = useState(null);

  useEffect(() => {
    const pollInterval = setInterval(async () => {
      try {
        const res = await fetch(`http://localhost:4000/api/v1/sessions/${sessionId}/status`);
        if (res.ok) {
          const data = await res.json();
          setSessionStatus(data.status);
          if (data.studentRollNumber) {
            setStudentRoll(data.studentRollNumber);
          }
        }
      } catch (err) {
        console.error("Backend polling error", err);
      }
    }, 2000);

    return () => clearInterval(pollInterval);
  }, [sessionId]);

  return (
    <div style={{ padding: 40, fontFamily: 'Segoe UI, sans-serif' }}>
      <h1>SPEMCS Online Placement Examination</h1>
      
      {sessionStatus !== 'Monitoring' ? (
        <div style={{ padding: 20, background: '#FFFBEB', border: '1px solid #FDE68A', borderRadius: 8 }}>
          <h3>Waiting for Endpoint Security Verification...</h3>
          <p>Please complete the SPEMCS verification dialog on your screen to begin the examination.</p>
          <p>Current Status: <strong>{sessionStatus}</strong></p>
        </div>
      ) : (
        <div style={{ padding: 20, background: '#F0FDF4', border: '1px solid #BBF7D0', borderRadius: 8 }}>
          <h3>Verification Complete & Monitoring Active</h3>
          <p>Candidate Roll Number: <strong>{studentRoll}</strong></p>
          <hr />
          <h2>Question 1: Data Structures</h2>
          <p>Explain the difference between a Binary Search Tree and a Red-Black Tree.</p>
          <textarea rows={6} cols={60} placeholder="Type your answer here..."></textarea>
          <br /><br />
          <button style={{ padding: '10px 20px', background: '#0284C7', color: 'white', border: 'none', borderRadius: 4 }}>Submit Answer</button>
        </div>
      )}
    </div>
  );
}
```

---

## 5. Machine Learning (ML) & AI Proctoring Architecture

### Process Behavior Anomaly Detection (ONNX in C#)
Train an Isolation Forest / XGBoost model in Python and run in-process ONNX inference inside the Endpoint Agent:

```csharp
using Microsoft.ML.OnnxRuntime;
using Microsoft.ML.OnnxRuntime.Tensors;

public class MlProcessClassifier : IProcessClassifier
{
    private readonly InferenceSession _onnxSession;
    public MlProcessClassifier(string modelPath) => _onnxSession = new InferenceSession(modelPath);

    public ClassificationResult Classify(ProcessInfo process)
    {
        var features = new float[] { process.ProcessId, process.HasVisibleWindow ? 1f : 0f };
        var container = new List<NamedOnnxValue> { NamedOnnxValue.CreateFromTensor("float_input", new DenseTensor<float>(features, new[] { 1, 2 })) };

        using var results = _onnxSession.Run(container);
        var score = results.First().AsEnumerable<float>().First();
        bool isAnomaly = score < -0.5f;

        return new ClassificationResult(
            isAnomaly ? Classification.Suspicious : Classification.Allowed,
            isAnomaly ? "ml-anomaly-detected" : "ml-normal-process",
            "ML Process Classifier", null, null,
            isAnomaly ? $"ML score anomaly ({score:F2})" : "Normal behavior");
    }
}
```
