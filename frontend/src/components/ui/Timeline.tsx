/**
 * Timeline - Chronological event timeline for reports and monitoring.
 */
import React from 'react';
import { AlertTriangle, Clock, Monitor, User, Activity } from 'lucide-react';

export interface TimelineEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  device_name?: string;
  student_roll_number?: string;
  process_name?: string;
  classification?: string;
  reason?: string;
}

interface TimelineProps {
  events: TimelineEvent[];
  title?: string;
  maxHeight?: string;
}

export function Timeline({ events, title, maxHeight = '600px' }: TimelineProps) {
  const getEventColor = (classification?: string, eventType?: string) => {
    if (classification === 'unauthorized') return 'bg-red-500';
    if (eventType?.toLowerCase().includes('blocked')) return 'bg-red-500';
    if (eventType?.toLowerCase().includes('focus_lost')) return 'bg-amber-500';
    if (eventType?.toLowerCase().includes('opened')) return 'bg-blue-500';
    if (eventType?.toLowerCase().includes('closed')) return 'bg-green-500';
    return 'bg-white/30';
  };

  const getEventIcon = (eventType?: string) => {
    if (eventType?.toLowerCase().includes('unauthorized') || eventType?.toLowerCase().includes('blocked'))
      return <AlertTriangle className="w-3.5 h-3.5" />;
    if (eventType?.toLowerCase().includes('opened') || eventType?.toLowerCase().includes('closed'))
      return <Activity className="w-3.5 h-3.5" />;
    return <Clock className="w-3.5 h-3.5" />;
  };

  if (events.length === 0) {
    return (
      <div className="text-center py-12 text-white/30">
        <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p className="text-sm">No events to display</p>
      </div>
    );
  }

  return (
    <div>
      {title && <h3 className="text-sm font-medium text-white/60 mb-4">{title}</h3>}
      <div className="relative" style={{ maxHeight, overflowY: 'auto' }}>
        {/* Timeline line */}
        <div className="absolute left-4 top-0 bottom-0 w-px bg-white/10" />

        <div className="space-y-1">
          {events.map((event) => (
            <div key={event.event_id} className="relative pl-10 pr-2 py-2 hover:bg-white/5 rounded-lg transition-colors group">
              {/* Dot */}
              <div className={`absolute left-[11px] top-4 w-2.5 h-2.5 rounded-full ${getEventColor(event.classification, event.event_type)} ring-2 ring-[#1A0D06]`} />

              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                      event.classification === 'unauthorized'
                        ? 'bg-red-500/20 text-red-300'
                        : 'bg-white/10 text-white/60'
                    }`}>
                      {event.event_type}
                    </span>
                    {event.process_name && (
                      <span className="text-xs text-white/40 truncate">{event.process_name}</span>
                    )}
                  </div>

                  {event.reason && (
                    <p className="text-xs text-white/50 mt-0.5 truncate">{event.reason}</p>
                  )}

                  <div className="flex items-center gap-3 mt-1 text-white/30 text-[11px]">
                    {event.device_name && (
                      <span className="flex items-center gap-1">
                        <Monitor className="w-3 h-3" />{event.device_name}
                      </span>
                    )}
                    {event.student_roll_number && (
                      <span className="flex items-center gap-1">
                        <User className="w-3 h-3" />{event.student_roll_number}
                      </span>
                    )}
                  </div>
                </div>

                <span className="text-[11px] text-white/30 whitespace-nowrap flex-shrink-0">
                  {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : ''}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
