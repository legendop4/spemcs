/**
 * DeviceTile - Live monitoring device card for exam proctoring.
 * Shows device status, student info, and latest alert.
 */
import React from 'react';
import { Monitor, User, AlertTriangle, Clock, Wifi, WifiOff } from 'lucide-react';
import { Badge } from './Badge';

interface DeviceTileProps {
  deviceName: string;
  deviceId: string;
  hardwareUuid?: string;
  studentRollNumber?: string;
  status: 'compliant' | 'violation' | 'offline' | 'pending' | 'monitoring';
  latestAlert?: {
    type: string;
    message: string;
    timestamp: string;
    severity: string;
  };
  onClick?: () => void;
}

export function DeviceTile({
  deviceName,
  deviceId,
  hardwareUuid,
  studentRollNumber,
  status,
  latestAlert,
  onClick,
}: DeviceTileProps) {
  const isViolation = status === 'violation';
  const isOffline = status === 'offline';

  return (
    <div
      onClick={onClick}
      className={`relative p-4 rounded-xl border backdrop-blur-sm transition-all cursor-pointer hover:scale-[1.02] ${
        isViolation
          ? 'border-red-500/60 bg-red-500/10 animate-pulse-subtle'
          : isOffline
          ? 'border-white/10 bg-white/5 opacity-60'
          : 'border-white/10 bg-white/5 hover:border-amber-500/30'
      }`}
    >
      {/* Status indicator dot */}
      <div className={`absolute top-3 right-3 w-2.5 h-2.5 rounded-full ${
        isViolation ? 'bg-red-500 animate-ping-slow' :
        isOffline ? 'bg-white/30' :
        status === 'monitoring' ? 'bg-green-500' :
        status === 'pending' ? 'bg-amber-500' :
        'bg-green-500'
      }`} />

      {/* Device name */}
      <div className="flex items-center gap-2 mb-3">
        <Monitor className="w-4 h-4 text-amber-400 flex-shrink-0" />
        <span className="text-sm font-medium text-white truncate">{deviceName}</span>
      </div>

      {/* Student */}
      {studentRollNumber && studentRollNumber !== 'PENDING' && (
        <div className="flex items-center gap-2 mb-2">
          <User className="w-3.5 h-3.5 text-white/40" />
          <span className="text-xs text-white/60">{studentRollNumber}</span>
        </div>
      )}

      {/* Status badge */}
      <div className="mb-2">
        <Badge variant={
          isViolation ? 'red' :
          isOffline ? 'gray' :
          status === 'monitoring' ? 'green' :
          status === 'pending' ? 'amber' :
          'green'
        }>
          {isViolation ? 'Violation' :
           isOffline ? 'Offline' :
           status === 'monitoring' ? 'Monitoring' :
           status === 'pending' ? 'Pending' :
           'Compliant'}
        </Badge>
      </div>

      {/* Latest alert */}
      {latestAlert && (
        <div className={`mt-2 p-2 rounded-lg text-xs ${
          latestAlert.severity === 'high' || latestAlert.severity === 'critical'
            ? 'bg-red-500/10 text-red-300'
            : 'bg-amber-500/10 text-amber-300'
        }`}>
          <div className="flex items-center gap-1 mb-1">
            <AlertTriangle className="w-3 h-3" />
            <span className="font-medium truncate">{latestAlert.type}</span>
          </div>
          <div className="flex items-center gap-1 text-white/40">
            <Clock className="w-3 h-3" />
            <span>{new Date(latestAlert.timestamp).toLocaleTimeString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}
