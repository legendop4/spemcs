"""
SPEMCS database models — matches the schema in the official architecture doc.
"""

from .base import Base
from .device import Device, DeviceStatus
from .exam import Exam, ExamStatus, ApprovedBrowser, ExamDevice, ExamDeviceStatus
from .session import ExamSession, SessionStatus
from .event import Event, Classification
from .alert import Alert
from .report import Report
from .lab import Lab, LabStatus
from .lab_device import LabDevice
from .user import User, UserRole
from .audit_log import AuditLog
from .policy import VendorProfile, NetworkPolicy, DevicePolicyState

__all__ = [
    "Base",
    "Device", "DeviceStatus",
    "Exam", "ExamStatus", "ApprovedBrowser",
    "ExamDevice", "ExamDeviceStatus",
    "ExamSession", "SessionStatus",
    "Event", "Classification",
    "Alert",
    "Report",
    "Lab", "LabStatus",
    "LabDevice",
    "User", "UserRole",
    "AuditLog",
    "VendorProfile",
    "NetworkPolicy",
    "DevicePolicyState",
]
