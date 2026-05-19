#!/usr/bin/env python3
"""
uds27_gui.py  –  PySide6 GUI for uds27_securityaccess_behavior_probe.py

UI/UX Refactor v2:
  - Three-zone layout: Left config | Center PoC dashboard | Right logs
  - PoC status cards (CAN, ECU pair, session, attempt progress, verdict)
  - Event timeline with color-coded badges
  - Tabbed right panel: Timeline / Detailed Log / Raw CAN
  - Clean toolbar replacing CMD bar
  - NRC meanings in plain language
  - CAN error cards

Usage:
    pip install PySide6
    python3 uds27_gui.py
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import (
    QProcess,
    Qt,
    QTimer,
    Signal,
    QSignalBlocker,
)
from PySide6.QtGui import QColor, QFont, QTextCursor, QClipboard
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
    QSizePolicy,
    QProgressBar,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCRIPT_NAME = "uds27_securityaccess_behavior_probe.py"

MODES = [
    ("UDS-13 / key-without-seed",       "key-without-seed"),
    ("UDS-14 / seed-timeout-key",        "seed-timeout-key"),
    ("UDS-16 / one-seed-many-keys",      "one-seed-many-keys"),
    ("UDS-17 / seed-key-exchange-loop",  "seed-key-exchange-loop"),
    ("UDS-18 / penalty-then-seed",       "penalty-then-seed"),
    ("UDS-19 / multi-seed-response",     "multi-seed-response"),
]

KEY_POLICIES = ["valid", "invalid-bitflip", "format-random", "zero", "pattern", "explicit"]

REPEATED_MODES = {"one-seed-many-keys", "seed-key-exchange-loop", "penalty-then-seed"}

NRC_MEANINGS = {
    0x10: ("generalReject",              "General reject – request not accepted"),
    0x11: ("serviceNotSupported",        "Service not supported by ECU"),
    0x12: ("subFunctionNotSupported",    "Sub-function not supported"),
    0x13: ("incorrectMessageLength",     "Incorrect message length or format"),
    0x22: ("conditionsNotCorrect",       "Conditions not correct – ECU not ready"),
    0x24: ("requestSequenceError",       "Sequence error – request out of order"),
    0x25: ("noResponseFromSubnetComponent", "No response from subnet component"),
    0x31: ("requestOutOfRange",          "Request out of range"),
    0x33: ("securityAccessDenied",       "Security access denied"),
    0x35: ("invalidKey",                 "Invalid key – key value was rejected"),
    0x36: ("exceededNumberOfAttempts",   "Exceeded number of attempts – ECU locked"),
    0x37: ("requiredTimeDelayNotExpired","Time delay not expired – too soon to retry"),
    0x78: ("requestCorrectlyReceivedResponsePending", "Response pending – ECU still processing"),
    0x7E: ("subFunctionNotSupportedInActiveSession", "Sub-function not supported in active session"),
    0x7F: ("serviceNotSupportedInActiveSession", "Service not supported in active session"),
}

# Colour palette (dark engineering theme)
C_BG       = "#14171B"
C_PANEL    = "#1C2027"
C_PANEL2   = "#20252C"
C_BORDER   = "#2E3540"
C_BORDER2  = "#3A4455"
C_TEXT     = "#C8CDD6"
C_TEXT2    = "#8A95A3"
C_DIM      = "#5A6475"
C_ACCENT   = "#3B82F6"
C_ACCENT2  = "#60A5FA"
C_OK       = "#22C55E"
C_OK_BG    = "#0D2818"
C_WARN     = "#EAB308"
C_WARN_BG  = "#1A1600"
C_ORANGE   = "#F97316"
C_ORANGE_BG= "#1A0D00"
C_ERROR    = "#EF4444"
C_ERROR_BG = "#1A0808"
C_PURPLE   = "#A78BFA"
C_BLUE_BG  = "#0A1628"
C_HEADER   = "#1A2033"

STYLE_SHEET = f"""
QMainWindow, QWidget {{
    background: {C_BG};
    color: {C_TEXT};
    font-family: "JetBrains Mono", "Consolas", "Courier New", monospace;
    font-size: 12px;
}}
QGroupBox {{
    border: 1px solid {C_BORDER};
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 6px;
    background: {C_PANEL};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 6px;
    color: {C_ACCENT2};
    font-weight: bold;
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}
QLabel {{
    color: {C_TEXT};
}}
QLineEdit, QComboBox, QSpinBox {{
    background: {C_BG};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    padding: 3px 7px;
    color: {C_TEXT};
    selection-background-color: {C_ACCENT};
}}
QLineEdit:focus, QComboBox:focus {{
    border: 1px solid {C_ACCENT};
}}
QComboBox QAbstractItemView {{
    background: {C_PANEL};
    border: 1px solid {C_BORDER};
    selection-background-color: {C_ACCENT};
    color: {C_TEXT};
}}
QPushButton {{
    background: {C_HEADER};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    padding: 5px 12px;
    color: {C_TEXT};
    min-width: 60px;
    font-size: 12px;
}}
QPushButton:hover {{
    background: {C_ACCENT};
    border-color: {C_ACCENT};
    color: #ffffff;
}}
QPushButton:disabled {{
    color: {C_DIM};
    border-color: {C_BORDER};
    background: {C_BG};
}}
QPushButton#run_btn {{
    background: #0e3320;
    border: 1px solid #22C55E55;
    color: #4ade80;
    font-weight: bold;
    letter-spacing: 0.5px;
}}
QPushButton#run_btn:hover {{
    background: #15803d;
    border-color: {C_OK};
    color: #ffffff;
}}
QPushButton#run_all_btn {{
    background: #0e3320;
    border: 1px solid #22C55E55;
    color: #4ade80;
    font-weight: bold;
}}
QPushButton#run_all_btn:hover {{
    background: #15803d;
    border-color: {C_OK};
    color: #ffffff;
}}
QPushButton#stop_btn {{
    background: #2d0a0a;
    border: 1px solid #EF444455;
    color: #f87171;
    font-weight: bold;
}}
QPushButton#stop_btn:hover {{
    background: #991b1b;
    border-color: {C_ERROR};
    color: #ffffff;
}}
QPushButton#reset_ecu_btn {{
    background: #2a1500;
    border: 1px solid #F9731655;
    color: #fb923c;
    font-weight: bold;
}}
QPushButton#reset_ecu_btn:hover {{
    background: #9a3412;
    border-color: {C_ORANGE};
    color: #ffffff;
}}
QPushButton#reset_all_btn {{
    background: #2d0a0a;
    border: 1px solid #EF444455;
    color: #f87171;
    font-weight: bold;
}}
QPushButton#reset_all_btn:hover {{
    background: #991b1b;
    border-color: {C_ERROR};
    color: #ffffff;
}}
QTextEdit {{
    background: #0A0D11;
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    color: {C_TEXT};
    font-family: "JetBrains Mono", "Consolas", "Courier New", monospace;
    font-size: 11px;
}}
QTableWidget {{
    background: {C_BG};
    border: 1px solid {C_BORDER};
    gridline-color: {C_BORDER};
    color: {C_TEXT};
    selection-background-color: #1E3A5F;
    alternate-background-color: {C_PANEL};
}}
QTableWidget::item {{
    padding: 3px 6px;
    border: none;
}}
QHeaderView::section {{
    background: {C_HEADER};
    color: {C_DIM};
    border: none;
    border-right: 1px solid {C_BORDER};
    border-bottom: 1px solid {C_BORDER};
    padding: 4px 8px;
    font-size: 10px;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}}
QCheckBox {{
    color: {C_TEXT};
    spacing: 5px;
}}
QCheckBox::indicator {{
    width: 13px;
    height: 13px;
    border: 1px solid {C_BORDER};
    border-radius: 2px;
    background: {C_BG};
}}
QCheckBox::indicator:checked {{
    background: {C_ACCENT};
    border-color: {C_ACCENT};
}}
QScrollBar:vertical {{
    background: {C_BG};
    width: 6px;
    margin: 0;
}}
QScrollBar::handle:vertical {{
    background: {C_BORDER2};
    border-radius: 3px;
    min-height: 20px;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}
QScrollBar:horizontal {{
    background: {C_BG};
    height: 6px;
}}
QScrollBar::handle:horizontal {{
    background: {C_BORDER2};
    border-radius: 3px;
}}
QFrame[frameShape="4"] {{
    color: {C_BORDER};
}}
QToolButton {{
    background: transparent;
    border: none;
    color: {C_DIM};
    font-size: 11px;
}}
QToolButton:hover {{
    color: {C_TEXT};
}}
QSplitter::handle {{
    background: {C_BORDER};
}}
QTabWidget::pane {{
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    background: {C_PANEL};
}}
QTabBar::tab {{
    background: {C_BG};
    border: 1px solid {C_BORDER};
    border-bottom: none;
    padding: 5px 14px;
    color: {C_DIM};
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 0.5px;
    min-width: 80px;
}}
QTabBar::tab:selected {{
    background: {C_PANEL};
    color: {C_ACCENT2};
    border-top: 2px solid {C_ACCENT};
    border-bottom: none;
}}
QTabBar::tab:hover:!selected {{
    color: {C_TEXT};
    background: {C_PANEL2};
}}
QProgressBar {{
    background: {C_BG};
    border: 1px solid {C_BORDER};
    border-radius: 3px;
    text-align: center;
    color: {C_TEXT};
    font-size: 11px;
    max-height: 14px;
}}
QProgressBar::chunk {{
    background: {C_ACCENT};
    border-radius: 2px;
}}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_valid_hex_id(text: str) -> bool:
    text = text.strip().replace("0x", "").replace("0X", "")
    if not text:
        return False
    try:
        int(text, 16)
        return True
    except ValueError:
        return False


def hex_to_int(text: str) -> int:
    return int(text.strip().replace("0x", "").replace("0X", ""), 16)


def validate_byte_hex(text: str) -> bool:
    try:
        v = int(text.strip(), 16)
        return 0 <= v <= 0xFF
    except ValueError:
        return False


def bhex(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def nrc_label(code: int) -> str:
    info = NRC_MEANINGS.get(code)
    if info:
        return f"NRC 0x{code:02X} – {info[0]}"
    return f"NRC 0x{code:02X}"


def nrc_description(code: int) -> str:
    info = NRC_MEANINGS.get(code)
    if info:
        return info[1]
    return f"Unknown NRC code 0x{code:02X}"


# ---------------------------------------------------------------------------
# Collapsible section widget
# ---------------------------------------------------------------------------

class CollapsibleSection(QWidget):
    def __init__(self, title: str, parent=None, start_open=False):
        super().__init__(parent)
        self._collapsed = not start_open

        self.toggle_btn = QToolButton()
        self.toggle_btn.setText(f"{'▼' if start_open else '▶'}  {title}")
        self.toggle_btn.setCheckable(True)
        self.toggle_btn.setChecked(start_open)
        self.toggle_btn.setStyleSheet(
            f"QToolButton {{ color: {C_ACCENT2}; font-weight: bold; font-size: 10px;"
            f" letter-spacing: 1px; text-transform: uppercase; padding: 4px 2px; }}"
        )
        self.toggle_btn.toggled.connect(self._on_toggle)

        self.content = QWidget()
        self.content.setVisible(start_open)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        layout.addWidget(self.toggle_btn)
        layout.addWidget(self.content)

    def _on_toggle(self, checked: bool):
        self.content.setVisible(checked)
        arrow = "▼" if checked else "▶"
        txt = self.toggle_btn.text()
        txt = re.sub(r"^[▶▼]\s+", f"{arrow}  ", txt)
        self.toggle_btn.setText(txt)


# ---------------------------------------------------------------------------
# Status card widget
# ---------------------------------------------------------------------------

class StatusCard(QWidget):
    """A compact status card with label, value, and optional badge."""
    def __init__(self, label: str, value: str = "—", parent=None):
        super().__init__(parent)
        self.setFixedHeight(54)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 6, 10, 6)
        outer.setSpacing(2)

        self._lbl = QLabel(label.upper())
        self._lbl.setStyleSheet(f"color:{C_DIM}; font-size:9px; letter-spacing:1px; font-weight:bold;")
        outer.addWidget(self._lbl)

        self._val = QLabel(value)
        self._val.setStyleSheet(f"color:{C_TEXT}; font-size:13px; font-weight:bold;")
        self._val.setWordWrap(True)
        outer.addWidget(self._val)

        self.setStyleSheet(f"""
            StatusCard {{
                background: {C_PANEL2};
                border: 1px solid {C_BORDER};
                border-radius: 6px;
            }}
        """)

    def set_value(self, text: str, color: str = C_TEXT):
        self._val.setText(text)
        self._val.setStyleSheet(f"color:{color}; font-size:13px; font-weight:bold;")

    def set_label(self, text: str):
        self._lbl.setText(text.upper())


class VerdictCard(QWidget):
    """Large verdict banner displayed at the end of a run."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(60)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 8, 16, 8)

        self._icon = QLabel("◉")
        self._icon.setStyleSheet("font-size:22px;")
        layout.addWidget(self._icon)

        vbox = QVBoxLayout()
        vbox.setSpacing(0)
        self._title = QLabel("AWAITING RUN")
        self._title.setStyleSheet(f"font-size:14px; font-weight:bold; letter-spacing:2px; color:{C_DIM};")
        vbox.addWidget(self._title)
        self._sub = QLabel("—")
        self._sub.setStyleSheet(f"font-size:10px; color:{C_DIM};")
        vbox.addWidget(self._sub)
        layout.addLayout(vbox)
        layout.addStretch()

        self._update_style(C_BORDER, C_DIM)

    def _update_style(self, border: str, text: str):
        self.setStyleSheet(f"""
            VerdictCard {{
                background: {C_PANEL2};
                border: 1px solid {border};
                border-left: 4px solid {border};
                border-radius: 6px;
            }}
        """)

    def set_verdict(self, verdict: str, sub: str = ""):
        colors = {
            "SUCCESS":   (C_OK,     "◉", "#0D2818"),
            "UNLOCKED":  (C_OK,     "◉", "#0D2818"),
            "FAILED":    (C_ERROR,  "✕", "#1A0808"),
            "TIMEOUT":   (C_WARN,   "⏱", "#1A1600"),
            "NRC":       (C_ORANGE, "⚠", "#1A0D00"),
            "CAN ERROR": (C_ERROR,  "⚡", "#1A0808"),
            "LOCKED":    (C_ORANGE, "🔒", "#1A0D00"),
            "RUNNING":   (C_ACCENT, "▶", C_BLUE_BG),
            "STOPPED":   (C_DIM,    "■", C_PANEL2),
        }
        col, icon, bg = colors.get(verdict.upper(), (C_DIM, "◉", C_PANEL2))
        self._icon.setText(icon)
        self._icon.setStyleSheet(f"font-size:22px; color:{col};")
        self._title.setText(verdict.upper())
        self._title.setStyleSheet(f"font-size:14px; font-weight:bold; letter-spacing:2px; color:{col};")
        self._sub.setText(sub or "—")
        self._sub.setStyleSheet(f"font-size:10px; color:{C_TEXT2};")
        self.setStyleSheet(f"""
            VerdictCard {{
                background: {bg};
                border: 1px solid {col}55;
                border-left: 4px solid {col};
                border-radius: 6px;
            }}
        """)


# ---------------------------------------------------------------------------
# CAN Error card
# ---------------------------------------------------------------------------

class CanErrorCard(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setVisible(False)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(4)

        hdr = QHBoxLayout()
        icon = QLabel("⚡")
        icon.setStyleSheet(f"font-size:16px; color:{C_ERROR};")
        hdr.addWidget(icon)
        title = QLabel("CAN BUS ERROR")
        title.setStyleSheet(f"color:{C_ERROR}; font-weight:bold; font-size:12px; letter-spacing:1px;")
        hdr.addWidget(title)
        hdr.addStretch()
        self._dismiss = QPushButton("×")
        self._dismiss.setMaximumWidth(24)
        self._dismiss.setStyleSheet(f"background:transparent; border:none; color:{C_DIM}; font-size:14px;")
        self._dismiss.clicked.connect(lambda: self.setVisible(False))
        hdr.addWidget(self._dismiss)
        layout.addLayout(hdr)

        self._problem = QLabel("Problem: —")
        self._problem.setStyleSheet(f"color:{C_TEXT}; font-size:11px;")
        layout.addWidget(self._problem)

        self._cause = QLabel("Likely cause: —")
        self._cause.setStyleSheet(f"color:{C_TEXT2}; font-size:11px;")
        layout.addWidget(self._cause)

        self._action = QLabel("→ Suggested: —")
        self._action.setStyleSheet(f"color:{C_WARN}; font-size:11px;")
        layout.addWidget(self._action)

        self.setStyleSheet(f"""
            CanErrorCard {{
                background: {C_ERROR_BG};
                border: 1px solid {C_ERROR}66;
                border-left: 4px solid {C_ERROR};
                border-radius: 6px;
            }}
        """)

    def show_error(self, raw_line: str):
        self.setVisible(True)
        if "no such device" in raw_line.lower() or "errno 19" in raw_line.lower():
            self._problem.setText("Problem: CAN interface not available")
            self._cause.setText("Likely cause: wrong interface name, interface down, missing vcan/can setup, or insufficient permissions")
            self._action.setText("→ Run: ip link show  |  sudo ip link set can0 up type can bitrate 500000")
        elif "permission" in raw_line.lower():
            self._problem.setText("Problem: Permission denied on CAN interface")
            self._cause.setText("Likely cause: insufficient user permissions")
            self._action.setText("→ Add user to 'can' group or run with sudo")
        elif "timeout" in raw_line.lower():
            self._problem.setText("Problem: CAN bus timeout")
            self._cause.setText("Likely cause: ECU not responding, wrong bitrate, or bus not active")
            self._action.setText("→ Verify ECU power, CAN bitrate, and termination")
        else:
            self._problem.setText(f"Problem: {raw_line[:80]}")
            self._cause.setText("Likely cause: CAN bus or interface configuration error")
            self._action.setText("→ Check CAN interface with: candump can0")


# ---------------------------------------------------------------------------
# Target table
# ---------------------------------------------------------------------------

TARGET_COLS = ["✓", "Name", "TX ID", "RX ID", "Session", "Seed", "Mode", "Attempts"]
COL_EN, COL_NAME, COL_TX, COL_RX, COL_SESSION, COL_SEED, COL_MODE, COL_ATT = range(8)


class TargetTable(QWidget):
    def __init__(self, parent=None, config_provider=None):
        super().__init__(parent)
        self.config_provider = config_provider
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Primary action row
        row1 = QHBoxLayout()
        row1.setSpacing(4)
        for label, slot, w in [
            ("Add",       self._add,             50),
            ("Update Sel",self._update_selected, 85),
            ("Duplicate", self._duplicate,        80),
            ("Remove",    self._remove,           65),
        ]:
            b = QPushButton(label)
            b.setMaximumWidth(w)
            b.clicked.connect(slot)
            b.setStyleSheet("font-size:11px; padding:3px 6px;")
            row1.addWidget(b)
        row1.addStretch()

        row2 = QHBoxLayout()
        row2.setSpacing(4)
        for label, slot, w in [
            ("Clear All",  self.clear,   75),
            ("Load CSV",   self._load_csv, 75),
            ("Save CSV",   self._save_csv, 75),
        ]:
            b = QPushButton(label)
            b.setMaximumWidth(w)
            b.clicked.connect(slot)
            b.setStyleSheet("font-size:11px; padding:3px 6px;")
            row2.addWidget(b)
        row2.addStretch()

        layout.addLayout(row1)
        layout.addLayout(row2)

        self.table = QTableWidget(0, len(TARGET_COLS))
        self.table.setHorizontalHeaderLabels(TARGET_COLS)
        header = self.table.horizontalHeader()
        for col in range(len(TARGET_COLS)):
            header.setSectionResizeMode(col, QHeaderView.Interactive)
        header.setSectionResizeMode(COL_MODE, QHeaderView.Stretch)
        self.table.setColumnWidth(COL_EN, 30)
        self.table.setColumnWidth(COL_NAME, 90)
        self.table.setColumnWidth(COL_TX, 60)
        self.table.setColumnWidth(COL_RX, 60)
        self.table.setColumnWidth(COL_SESSION, 62)
        self.table.setColumnWidth(COL_SEED, 48)
        self.table.setColumnWidth(COL_ATT, 62)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setMinimumHeight(100)
        layout.addWidget(self.table)

    def _make_row(self, name="target", tx="681", rx="601", session="03",
                  seed="01", mode="one-seed-many-keys", attempts="10", enabled=True):
        row = self.table.rowCount()
        self.table.insertRow(row)

        chk = QCheckBox()
        chk.setChecked(enabled)
        chk.setStyleSheet("margin-left: 6px;")
        self.table.setCellWidget(row, COL_EN, chk)

        for col, val in [
            (COL_NAME,    name),
            (COL_TX,      tx),
            (COL_RX,      rx),
            (COL_SESSION, session),
            (COL_SEED,    seed),
            (COL_ATT,     attempts),
        ]:
            item = QTableWidgetItem(val)
            self.table.setItem(row, col, item)

        combo = QComboBox()
        for label, value in MODES:
            combo.addItem(label, value)
        idx = next((i for i, (_, v) in enumerate(MODES) if v == mode), 2)
        combo.setCurrentIndex(idx)
        combo.setStyleSheet(f"background:{C_BG}; border:none; color:{C_TEXT}; font-size:11px;")
        self.table.setCellWidget(row, COL_MODE, combo)
        self.table.setRowHeight(row, 22)

    def _config_defaults(self) -> dict:
        if callable(self.config_provider):
            try:
                return self.config_provider() or {}
            except Exception:
                return {}
        return {}

    def _add(self):
        cfg = self._config_defaults()
        self._make_row(**{k: cfg.get(k, v) for k, v in [
            ("name", "target"), ("tx", "681"), ("rx", "601"),
            ("session", "03"), ("seed", "01"),
            ("mode", "one-seed-many-keys"), ("attempts", "10"), ("enabled", True)
        ]})

    def clear(self):
        self.table.setRowCount(0)

    def _set_cell(self, row: int, col: int, value: str):
        item = self.table.item(row, col)
        if item is None:
            item = QTableWidgetItem(value)
            self.table.setItem(row, col, item)
        else:
            item.setText(value)

    def _set_mode(self, row: int, mode: str):
        combo = self.table.cellWidget(row, COL_MODE)
        if not combo:
            return
        idx = next((i for i, (_, v) in enumerate(MODES) if v == mode), -1)
        if idx >= 0:
            blocker = QSignalBlocker(combo)
            combo.setCurrentIndex(idx)
            del blocker

    @staticmethod
    def _is_auto_name(name: str) -> bool:
        n = (name or "").strip().lower()
        return not n or n.startswith("target") or "→" in n or "->" in n

    def update_row_from_config(self, row: int, cfg: dict):
        if row < 0 or row >= self.table.rowCount():
            return
        tx = cfg.get("tx", self._cell(row, COL_TX))
        rx = cfg.get("rx", self._cell(row, COL_RX))
        if self._is_auto_name(self._cell(row, COL_NAME)):
            self._set_cell(row, COL_NAME, cfg.get("name", f"{tx}→{rx}"))
        self._set_cell(row, COL_TX, tx)
        self._set_cell(row, COL_RX, rx)
        self._set_cell(row, COL_SESSION, cfg.get("session", self._cell(row, COL_SESSION)))
        self._set_cell(row, COL_SEED, cfg.get("seed", self._cell(row, COL_SEED)))
        self._set_cell(row, COL_ATT, cfg.get("attempts", self._cell(row, COL_ATT)))
        self._set_mode(row, cfg.get("mode", self._mode_value(row)))

    def sync_from_config(self, cfg: dict):
        if self.table.rowCount() == 0:
            return
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()))
        if not rows:
            rows = [0]
        for r in rows:
            self.update_row_from_config(r, cfg)

    def _update_selected(self):
        cfg = self._config_defaults()
        if not cfg:
            return
        self.sync_from_config(cfg)

    def _duplicate(self):
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()))
        if not rows:
            return
        for r in rows:
            self._make_row(
                name=self._cell(r, COL_NAME) + "_copy",
                tx=self._cell(r, COL_TX),
                rx=self._cell(r, COL_RX),
                session=self._cell(r, COL_SESSION),
                seed=self._cell(r, COL_SEED),
                mode=self._mode_value(r),
                attempts=self._cell(r, COL_ATT),
                enabled=self._enabled(r),
            )

    def _remove(self):
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()), reverse=True)
        for r in rows:
            self.table.removeRow(r)

    def _cell(self, row, col) -> str:
        item = self.table.item(row, col)
        return item.text().strip() if item else ""

    def _enabled(self, row) -> bool:
        chk = self.table.cellWidget(row, COL_EN)
        return chk.isChecked() if chk else False

    def _mode_value(self, row) -> str:
        combo = self.table.cellWidget(row, COL_MODE)
        return combo.currentData() if combo else "one-seed-many-keys"

    def rows(self) -> List[dict]:
        result = []
        for r in range(self.table.rowCount()):
            result.append({
                "enabled":  self._enabled(r),
                "name":     self._cell(r, COL_NAME),
                "tx":       self._cell(r, COL_TX),
                "rx":       self._cell(r, COL_RX),
                "session":  self._cell(r, COL_SESSION),
                "seed":     self._cell(r, COL_SEED),
                "mode":     self._mode_value(r),
                "attempts": self._cell(r, COL_ATT),
            })
        return result

    def selected_rows(self) -> List[dict]:
        sel_rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()))
        all_rows = self.rows()
        return [all_rows[r] for r in sel_rows]

    def _save_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save target list", "targets.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["enabled","name","tx","rx","session","seed","mode","attempts"])
            w.writeheader()
            w.writerows(self.rows())

    def _load_csv(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load target list", "", "CSV (*.csv)")
        if not path:
            return
        with open(path, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self._make_row(
                    name=row.get("name","target"),
                    tx=row.get("tx","681"),
                    rx=row.get("rx","601"),
                    session=row.get("session","03"),
                    seed=row.get("seed","01"),
                    mode=row.get("mode","one-seed-many-keys"),
                    attempts=row.get("attempts","10"),
                    enabled=row.get("enabled","True").lower() != "false",
                )


# ---------------------------------------------------------------------------
# Event timeline panel
# ---------------------------------------------------------------------------

ESSENTIAL_PATTERNS = [
    re.compile(r"\bTX\b|\bRX\b|\bsession-\w+\b|\bkey-attempt\b|\bexchange-\b|\bpros\b", re.I),
    re.compile(r"NRC\s+[0-9A-Fa-f]{2}", re.I),
    re.compile(r"\bPOS\b|\bpositive\b|\bseed\b.*len=", re.I),
    re.compile(r"\bSTART\b|\bVERDICT\b|\bRESULT\b|\bDONE\b|\babort\b|\bfail\b|\bpass\b|\bweak\b|\bunlocked\b|\breview\b", re.I),
    re.compile(r"^\[target\]"),
    re.compile(r"\bERROR\b|\bexception\b|\binterrupt", re.I),
    re.compile(r"cannot open|no such device|errno", re.I),
]


def classify_line(line: str):
    """Return (color, badge_text) for a log line."""
    upper = line.upper()
    if "NRC 35" in upper or "INVALIDKEY" in upper.replace(" ", ""):
        return C_WARN, "NRC·35"
    if "NRC 36" in upper:
        return C_ORANGE, "NRC·36"
    if "NRC 37" in upper:
        return C_ORANGE, "NRC·37"
    if "NRC 24" in upper:
        return C_WARN, "NRC·24"
    if "NRC 78" in upper:
        return C_BLUE_BG, "PEND"
    m = re.search(r"NRC\s+([0-9A-Fa-f]{2})", line, re.I)
    if m:
        return C_ORANGE, f"NRC·{m.group(1).upper()}"
    if any(x in upper for x in [" OK", "POSITIVE", "PASS", "UNLOCKED", "SUCCESS"]):
        return C_OK, "OK"
    if any(x in upper for x in ["ERROR", "ABORT", "FAIL", "INTERRUPT", "CANNOT OPEN"]):
        return C_ERROR, "ERR"
    if any(x in upper for x in ["VERDICT", "RESULT", "DONE"]):
        return C_ACCENT, "INFO"
    if "START" in upper:
        return C_ACCENT, "START"
    if "SEED" in upper and "LEN=" in upper.replace(" ", ""):
        return C_PURPLE, "SEED"
    if any(x in upper for x in ["TX", "RX"]):
        return C_ACCENT2, "CAN"
    return C_TEXT2, "LOG"


class TimelinePanel(QWidget):
    """Styled event timeline with badge + message per line."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.view = QTextEdit()
        self.view.setReadOnly(True)
        self.view.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.view)

        self._step = 0

    def clear(self):
        self.view.clear()
        self._step = 0

    def append_event(self, line: str, target: str = ""):
        line = line.rstrip()
        if not line:
            return
        if not any(p.search(line) for p in ESSENTIAL_PATTERNS):
            return

        color, badge = classify_line(line)
        self._step += 1

        cursor = self.view.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = cursor.charFormat()

        # Step number
        fmt.setForeground(QColor(C_DIM))
        cursor.setCharFormat(fmt)
        cursor.insertText(f"{self._step:>3}  ")

        # Badge
        fmt.setForeground(QColor(color))
        fmt.setBackground(QColor(color + "22"))
        cursor.setCharFormat(fmt)
        cursor.insertText(f" {badge:^6} ")
        fmt.setBackground(QColor("transparent"))
        cursor.setCharFormat(fmt)

        # Space
        fmt.setForeground(QColor(C_DIM))
        cursor.setCharFormat(fmt)
        cursor.insertText("  ")

        # Message
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)

        # Enrich NRC lines
        m_nrc = re.search(r"NRC\s+([0-9A-Fa-f]{2})", line, re.I)
        if m_nrc:
            nrc_code = int(m_nrc.group(1), 16)
            desc = nrc_description(nrc_code)
            cursor.insertText(f"{line}  →  {desc}\n")
        else:
            cursor.insertText(f"{line}\n")

        self.view.setTextCursor(cursor)
        self.view.ensureCursorVisible()


# ---------------------------------------------------------------------------
# Log panel (tabbed: Timeline / Detailed / Raw)
# ---------------------------------------------------------------------------

class LogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, stretch=1)

        # Tab 1: Timeline
        self.timeline = TimelinePanel()
        self.tabs.addTab(self.timeline, "⚡  Timeline")

        # Tab 2: Detailed log
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.NoWrap)
        self.tabs.addTab(self.log_view, "📋  Detailed Log")

        # Tab 3: Raw CAN
        self.raw_view = QTextEdit()
        self.raw_view.setReadOnly(True)
        self.raw_view.setLineWrapMode(QTextEdit.NoWrap)
        self.tabs.addTab(self.raw_view, "🔌  Raw CAN")

        self._current_target = ""

    def set_target(self, name: str):
        self._current_target = name

    def append_raw(self, text: str):
        self.raw_view.moveCursor(QTextCursor.End)
        self.raw_view.insertPlainText(text)

    def append_line(self, line: str):
        """Append to both detailed log and timeline."""
        line = line.rstrip()
        if not line:
            return

        # Timeline (filtered)
        self.timeline.append_event(line, self._current_target)

        # Detailed log (all essential lines, colored)
        is_essential = any(p.search(line) for p in ESSENTIAL_PATTERNS)
        if not is_essential:
            return

        color, _ = classify_line(line)

        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(color))
        cursor.setCharFormat(fmt)
        prefix = f"[{self._current_target}] " if self._current_target else ""
        cursor.insertText(prefix + line + "\n")
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

    def append_summary_block(self, text: str):
        cursor = self.log_view.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = cursor.charFormat()
        fmt.setForeground(QColor(C_DIM))
        cursor.setCharFormat(fmt)
        cursor.insertText("─" * 60 + "\n")
        fmt.setForeground(QColor(C_ACCENT))
        cursor.setCharFormat(fmt)
        cursor.insertText(text + "\n")
        fmt.setForeground(QColor(C_DIM))
        cursor.setCharFormat(fmt)
        cursor.insertText("─" * 60 + "\n")
        self.log_view.setTextCursor(cursor)
        self.log_view.ensureCursorVisible()

    def clear(self):
        self.log_view.clear()
        self.raw_view.clear()
        self.timeline.clear()

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(None, "Save log", "run_log.txt", "Text (*.txt)")
        if path:
            with open(path, "w") as f:
                f.write("=== TIMELINE ===\n")
                f.write(self.timeline.view.toPlainText())
                f.write("\n\n=== DETAILED LOG ===\n")
                f.write(self.log_view.toPlainText())
                f.write("\n\n=== RAW CAN ===\n")
                f.write(self.raw_view.toPlainText())


# ---------------------------------------------------------------------------
# PoC Dashboard (center panel)
# ---------------------------------------------------------------------------

class PoCDashboard(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # Verdict banner
        self.verdict_card = VerdictCard()
        layout.addWidget(self.verdict_card)

        # CAN error banner
        self.can_error_card = CanErrorCard()
        layout.addWidget(self.can_error_card)

        # Status grid (2 rows × 3 cols)
        grid_widget = QWidget()
        grid = QHBoxLayout(grid_widget)
        grid.setSpacing(6)
        grid.setContentsMargins(0, 0, 0, 0)

        col1 = QVBoxLayout()
        col1.setSpacing(6)
        self.card_can    = StatusCard("CAN Status", "—")
        self.card_ecu    = StatusCard("ECU Pair", "—")
        col1.addWidget(self.card_can)
        col1.addWidget(self.card_ecu)

        col2 = QVBoxLayout()
        col2.setSpacing(6)
        self.card_mode   = StatusCard("Test Mode", "—")
        self.card_sess   = StatusCard("Session / SA", "—")
        col2.addWidget(self.card_mode)
        col2.addWidget(self.card_sess)

        col3 = QVBoxLayout()
        col3.setSpacing(6)
        self.card_att    = StatusCard("Attempt", "—")
        self.card_last   = StatusCard("Last Response", "—")
        col3.addWidget(self.card_att)
        col3.addWidget(self.card_last)

        grid.addLayout(col1)
        grid.addLayout(col2)
        grid.addLayout(col3)
        layout.addWidget(grid_widget)

        # Progress bar
        prog_widget = QWidget()
        prog_layout = QVBoxLayout(prog_widget)
        prog_layout.setContentsMargins(0, 0, 0, 0)
        prog_layout.setSpacing(2)
        prog_lbl = QLabel("ATTEMPT PROGRESS")
        prog_lbl.setStyleSheet(f"color:{C_DIM}; font-size:9px; letter-spacing:1px; font-weight:bold;")
        prog_layout.addWidget(prog_lbl)
        self.progress = QProgressBar()
        self.progress.setValue(0)
        prog_layout.addWidget(self.progress)
        layout.addWidget(prog_widget)

        # Log panel
        self.log_panel = LogPanel()
        layout.addWidget(self.log_panel, stretch=1)

        self._total_attempts = 0
        self._current_attempt = 0

    def reset(self):
        self.verdict_card.set_verdict("RUNNING", "Test in progress…")
        self.can_error_card.setVisible(False)
        self.card_can.set_value("—")
        self.card_ecu.set_value("—")
        self.card_mode.set_value("—")
        self.card_sess.set_value("—")
        self.card_att.set_value("—")
        self.card_last.set_value("—")
        self.progress.setValue(0)
        self._total_attempts = 0
        self._current_attempt = 0

    def set_idle(self):
        self.verdict_card.set_verdict("STOPPED", "Ready to run")
        self.card_can.set_value("—")

    def process_line(self, line: str):
        """Parse a log line and update dashboard cards."""
        upper = line.upper()

        # CAN open
        if "CAN" in upper and "TX=" in upper and "RX=" in upper:
            m = re.search(r"TX=0x([0-9A-Fa-f]+).*RX=0x([0-9A-Fa-f]+)", line, re.I)
            if m:
                self.card_ecu.set_value(f"TX:0x{m.group(1).upper()}  RX:0x{m.group(2).upper()}", C_ACCENT2)
                self.card_can.set_value("CONNECTED", C_OK)

        # CAN error
        if any(x in upper for x in ["CANNOT OPEN CAN", "ERRNO", "NO SUCH DEVICE"]):
            self.card_can.set_value("ERROR", C_ERROR)
            self.can_error_card.show_error(line)

        # START
        if "START" in upper:
            m = re.search(r"START\s+(\S+)", line, re.I)
            if m:
                self.card_ecu.set_value(m.group(1), C_TEXT)

        # Attempt counting
        m_att = re.search(r"attempt[:\s#]*(\d+)[/\s]*(?:of\s*)?(\d+)?", line, re.I)
        if m_att:
            cur = int(m_att.group(1))
            tot = int(m_att.group(2)) if m_att.group(2) else self._total_attempts
            self._current_attempt = cur
            if tot:
                self._total_attempts = tot
                self.progress.setMaximum(tot)
            if self._total_attempts:
                self.progress.setValue(cur)
                self.card_att.set_value(f"{cur} / {self._total_attempts}", C_TEXT)

        # Positive response
        if any(x in upper for x in [" OK", "POSITIVE", "PASS", "UNLOCKED"]):
            self.card_last.set_value("POSITIVE ✓", C_OK)

        # NRC
        m_nrc = re.search(r"NRC\s+([0-9A-Fa-f]{2})", line, re.I)
        if m_nrc:
            code = int(m_nrc.group(1), 16)
            info = NRC_MEANINGS.get(code)
            label = nrc_label(code)
            col = C_WARN if code in (0x35,) else C_ORANGE
            self.card_last.set_value(label, col)

        # Seed received
        if "SEED" in upper and "LEN=" in upper.replace(" ", ""):
            self.card_last.set_value("SEED RECEIVED", C_PURPLE)

        # Mode / session from args (if line contains them)
        m_mode = re.search(r"mode[:\s=]+(\S+)", line, re.I)
        if m_mode:
            self.card_mode.set_value(m_mode.group(1), C_TEXT)

        # Session
        m_sess = re.search(r"session[:\s=]+(\S+)", line, re.I)
        if m_sess:
            self.card_sess.set_value(m_sess.group(1).upper(), C_TEXT)

        # Final verdicts
        if "UNLOCKED" in upper or ("PASS" in upper and "VERDICT" in upper):
            self.verdict_card.set_verdict("SUCCESS", "Security access unlocked")
            self.progress.setStyleSheet("QProgressBar::chunk { background: " + C_OK + "; }")
        elif "FAIL" in upper and "VERDICT" in upper:
            self.verdict_card.set_verdict("FAILED", "Test completed with failure")
        elif "ABORT" in upper or ("ERROR" in upper and "CAN" in upper):
            self.verdict_card.set_verdict("CAN ERROR", line[:80])
        elif "TIMEOUT" in upper and "VERDICT" in upper:
            self.verdict_card.set_verdict("TIMEOUT", "ECU did not respond in time")
        elif "LOCKED" in upper and "VERDICT" in upper:
            self.verdict_card.set_verdict("LOCKED", "ECU locked after too many attempts")
        elif "NRC" in upper and "VERDICT" in upper:
            self.verdict_card.set_verdict("NRC", line[:80])
        elif "DONE" in upper:
            pass  # keep last verdict

    def update_config(self, tx: str, rx: str, mode: str, session: str, attempts: str):
        self.card_ecu.set_value(f"TX:{tx}  RX:{rx}", C_TEXT2)
        self.card_mode.set_value(mode, C_TEXT2)
        self.card_sess.set_value(f"Session {session}", C_TEXT2)
        try:
            n = int(attempts)
            self._total_attempts = n
            self.progress.setMaximum(n)
            self.card_att.set_value(f"0 / {n}", C_TEXT2)
        except ValueError:
            pass


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UDS-27  SecurityAccess Probe  |  PoC Dashboard")
        self.setMinimumSize(1240, 720)
        self.resize(1440, 860)

        self._process: Optional[QProcess] = None
        self._queue: List[dict] = []
        self._running_target: Optional[dict] = None
        self._summary_buf: List[str] = []
        self._in_summary = False

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(8, 6, 8, 6)
        root.setSpacing(6)
        
        # Create dashboard/log panel first because toolbar actions reference self.log_panel
        self.dashboard = PoCDashboard()
        self.log_panel = self.dashboard.log_panel  # alias for backward compatibility

        # ── Top toolbar ──────────────────────────────────────────────────
        root.addWidget(self._build_toolbar())

        # ── Three-zone splitter ──────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        root.addWidget(splitter, stretch=1)

        # LEFT: config
        left = self._build_left_panel()
        splitter.addWidget(left)

        # CENTER: PoC dashboard (status cards + log tabs)
        splitter.addWidget(self.dashboard)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([380, 1060])

        # Connect live cmd update
        self._connect_cmd_update()
        self._update_cmd_preview()
        self._update_key_policy_ui()

    # ------------------------------------------------------------------
    # Toolbar
    # ------------------------------------------------------------------

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(42)
        bar.setStyleSheet(f"background:{C_PANEL}; border-bottom:1px solid {C_BORDER}; border-radius:6px;")
        h = QHBoxLayout(bar)
        h.setContentsMargins(10, 4, 10, 4)
        h.setSpacing(6)

        # Title badge
        title = QLabel("UDS-27  SA PROBE")
        title.setStyleSheet(f"color:{C_ACCENT2}; font-weight:bold; font-size:13px; letter-spacing:2px; margin-right:12px;")
        h.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color:{C_BORDER};")
        h.addWidget(sep)

        # Primary actions
        self.run_btn = QPushButton("▶  Run Current")
        self.run_btn.setObjectName("run_btn")
        self.run_btn.setToolTip("Run probe with current Basic Config")
        self.run_btn.clicked.connect(self._run_current)
        h.addWidget(self.run_btn)

        self.run_sel_btn = QPushButton("Run Selected")
        self.run_sel_btn.setToolTip("Run selected rows from target list")
        self.run_sel_btn.clicked.connect(self._run_selected)
        h.addWidget(self.run_sel_btn)

        self.run_all_btn = QPushButton("Run All ✓")
        self.run_all_btn.setObjectName("run_all_btn")
        self.run_all_btn.setToolTip("Run all enabled targets")
        self.run_all_btn.clicked.connect(self._run_all_enabled)
        h.addWidget(self.run_all_btn)

        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setObjectName("stop_btn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        h.addWidget(self.stop_btn)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet(f"color:{C_BORDER};")
        h.addWidget(sep2)

        # Secondary actions
        self.reset_ecu_btn = QPushButton("⟳ Reset ECU")
        self.reset_ecu_btn.setObjectName("reset_ecu_btn")
        self.reset_ecu_btn.setToolTip("Send UDS hardReset to current TX ID")
        self.reset_ecu_btn.clicked.connect(self._hard_reset_current_ecu)
        h.addWidget(self.reset_ecu_btn)

        self.reset_all_btn = QPushButton("⟳ Reset ALL")
        self.reset_all_btn.setObjectName("reset_all_btn")
        self.reset_all_btn.setToolTip("Broadcast UDS hardReset to 0x6FF")
        self.reset_all_btn.clicked.connect(self._hard_reset_broadcast)
        h.addWidget(self.reset_all_btn)

        sep3 = QFrame()
        sep3.setFrameShape(QFrame.VLine)
        sep3.setStyleSheet(f"color:{C_BORDER};")
        h.addWidget(sep3)

        clr_btn = QPushButton("🗑 Clear Logs")
        clr_btn.setToolTip("Clear all log panels")
        clr_btn.clicked.connect(self._clear_logs)
        h.addWidget(clr_btn)

        save_btn = QPushButton("💾 Save Log")
        save_btn.setToolTip("Save run log to file")
        save_btn.clicked.connect(self.log_panel.save_log)
        h.addWidget(save_btn)

        report_btn = QPushButton("📄 PoC Report")
        report_btn.setToolTip("Export PoC report (JSON + text)")
        report_btn.clicked.connect(self._save_poc_report)
        h.addWidget(report_btn)

        h.addStretch()

        # CMD preview (collapsed, right side)
        sep4 = QFrame()
        sep4.setFrameShape(QFrame.VLine)
        sep4.setStyleSheet(f"color:{C_BORDER};")
        h.addWidget(sep4)

        cmd_lbl = QLabel("CMD:")
        cmd_lbl.setStyleSheet(f"color:{C_DIM}; font-size:10px;")
        h.addWidget(cmd_lbl)

        self.cmd_preview = QLineEdit()
        self.cmd_preview.setReadOnly(True)
        self.cmd_preview.setMaximumWidth(340)
        self.cmd_preview.setStyleSheet(f"color:{C_DIM}; font-size:10px; background:{C_BG}; border-color:{C_BORDER};")
        h.addWidget(self.cmd_preview)

        copy_btn = QPushButton("⧉")
        copy_btn.setMaximumWidth(28)
        copy_btn.setToolTip("Copy command to clipboard")
        copy_btn.setStyleSheet("min-width:28px; padding:4px;")
        copy_btn.clicked.connect(self._copy_cmd)
        h.addWidget(copy_btn)

        return bar

    # ------------------------------------------------------------------
    # Left panel: config + targets
    # ------------------------------------------------------------------

    def _build_left_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        scroll.setMinimumWidth(370)
        scroll.setMaximumWidth(420)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(6)

        layout.addWidget(self._build_basic_config())
        layout.addWidget(self._build_advanced_section())
        layout.addWidget(self._build_target_section())
        layout.addStretch()

        scroll.setWidget(inner)
        return scroll

    # ------------------------------------------------------------------
    # Build basic config panel
    # ------------------------------------------------------------------

    def _build_basic_config(self) -> QGroupBox:
        grp = QGroupBox("Basic Config")
        form = QVBoxLayout(grp)
        form.setSpacing(4)
        form.setContentsMargins(8, 12, 8, 8)

        def row(label, widget, stretch=False):
            h = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(145)
            lbl.setStyleSheet(f"color:{C_TEXT2}; font-size:11px;")
            h.addWidget(lbl)
            if stretch:
                h.addWidget(widget, stretch=1)
            else:
                h.addWidget(widget)
                h.addStretch()
            form.addLayout(h)

        def sep(text):
            lbl = QLabel(f"─  {text}")
            lbl.setStyleSheet(f"color:{C_DIM}; font-size:9px; letter-spacing:1px; margin-top:4px;")
            form.addWidget(lbl)

        sep("CAN")
        self.channel = QLineEdit("can0")
        self.channel.setMaximumWidth(120)
        row("Channel", self.channel)

        self.tx_id = QLineEdit("681")
        self.tx_id.setMaximumWidth(100)
        row("TX ID (Tester)", self.tx_id)

        self.rx_id = QLineEdit("601")
        self.rx_id.setMaximumWidth(100)
        row("RX ID (ECU)", self.rx_id)

        sep("UDS")
        self.mode_combo = QComboBox()
        for label, _ in MODES:
            self.mode_combo.addItem(label)
        self.mode_combo.setCurrentIndex(2)
        self.mode_combo.currentIndexChanged.connect(self._on_mode_change)
        row("Mode", self.mode_combo, stretch=True)

        self.session_flow = QLineEdit("03")
        self.session_flow.setMaximumWidth(140)
        row("Session flow", self.session_flow)

        self.seed_subfn = QLineEdit("01")
        self.seed_subfn.setMaximumWidth(44)
        self.seed_subfn.textChanged.connect(self._on_seed_subfn_change)
        row("Seed subfn", self.seed_subfn)

        self.key_subfn = QLineEdit("02")
        self.key_subfn.setMaximumWidth(44)
        row("Key subfn", self.key_subfn)

        self.attempts = QLineEdit("10")
        self.attempts.setMaximumWidth(55)
        row("Attempts", self.attempts)

        self.key_policy = QComboBox()
        for p in KEY_POLICIES:
            self.key_policy.addItem(p)
        self.key_policy.setCurrentIndex(KEY_POLICIES.index("invalid-bitflip"))
        self.key_policy.currentIndexChanged.connect(self._update_key_policy_ui)
        row("Key policy", self.key_policy)

        # Conditional key fields
        self.key_hex_row = QHBoxLayout()
        kh_lbl = QLabel("Explicit key hex")
        kh_lbl.setFixedWidth(145)
        kh_lbl.setStyleSheet(f"color:{C_TEXT2}; font-size:11px;")
        self.key_hex = QLineEdit()
        self.key_hex.setPlaceholderText("AABBCCDD…")
        self.key_hex_row.addWidget(kh_lbl)
        self.key_hex_row.addWidget(self.key_hex, stretch=1)
        form.addLayout(self.key_hex_row)

        self.pattern_byte_row = QHBoxLayout()
        pb_lbl = QLabel("Pattern byte")
        pb_lbl.setFixedWidth(145)
        pb_lbl.setStyleSheet(f"color:{C_TEXT2}; font-size:11px;")
        self.pattern_byte = QLineEdit("AA")
        self.pattern_byte.setMaximumWidth(44)
        self.pattern_byte_row.addWidget(pb_lbl)
        self.pattern_byte_row.addWidget(self.pattern_byte)
        self.pattern_byte_row.addStretch()
        form.addLayout(self.pattern_byte_row)

        sep("Timing")
        self.delay = QLineEdit("0.2")
        self.delay.setMaximumWidth(65)
        row("Delay between attempts", self.delay)

        self.timeout = QLineEdit("1.0")
        self.timeout.setMaximumWidth(65)
        row("Response timeout", self.timeout)

        return grp

    # ------------------------------------------------------------------
    # Build advanced options collapsible
    # ------------------------------------------------------------------

    def _build_advanced_section(self) -> CollapsibleSection:
        section = CollapsibleSection("Advanced Options")
        layout = QVBoxLayout(section.content)
        layout.setContentsMargins(4, 0, 4, 4)
        layout.setSpacing(4)

        def row(label, widget, hint=""):
            h = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(145)
            lbl.setStyleSheet(f"color:{C_TEXT2}; font-size:11px;")
            h.addWidget(lbl)
            h.addWidget(widget)
            if hint:
                hl = QLabel(hint)
                hl.setStyleSheet(f"color:{C_DIM}; font-size:10px;")
                h.addWidget(hl)
            h.addStretch()
            layout.addLayout(h)

        def chk_row(label, attr, default=False):
            chk = QCheckBox(label)
            chk.setChecked(default)
            chk.setStyleSheet("font-size:11px;")
            setattr(self, attr, chk)
            layout.addWidget(chk)

        def sep(text):
            lbl = QLabel(f"─  {text}")
            lbl.setStyleSheet(f"color:{C_DIM}; font-size:9px; letter-spacing:1px; margin-top:4px;")
            layout.addWidget(lbl)

        sep("CAN / ISO-TP")
        self.interface = QLineEdit("socketcan")
        self.interface.setMaximumWidth(100)
        row("Interface", self.interface)

        chk_row("Extended ID (29-bit)", "extended_id_chk")

        self.padding = QLineEdit("00")
        self.padding.setMaximumWidth(44)
        row("Padding byte", self.padding)

        self.fc_bs = QLineEdit("00")
        self.fc_bs.setMaximumWidth(44)
        row("FC Block Size", self.fc_bs)

        self.fc_stmin = QLineEdit("00")
        self.fc_stmin.setMaximumWidth(44)
        row("FC STmin", self.fc_stmin)

        self.request_stmin = QLineEdit("0.0")
        self.request_stmin.setMaximumWidth(65)
        row("Request STmin (s)", self.request_stmin)

        self.fc_wait_timeout = QLineEdit("3.0")
        self.fc_wait_timeout.setMaximumWidth(65)
        row("FC wait timeout (s)", self.fc_wait_timeout, "SendKey FF → FC")

        chk_row("Drain before run", "drain_before_run_chk")

        sep("Timing")
        self.resp_pending_timeout = QLineEdit("5.0")
        self.resp_pending_timeout.setMaximumWidth(65)
        row("Response pending TO (s)", self.resp_pending_timeout)

        self.post_session_delay = QLineEdit("0.05")
        self.post_session_delay.setMaximumWidth(65)
        row("Post-session delay (s)", self.post_session_delay)

        self.key_delay = QLineEdit("0.05")
        self.key_delay.setMaximumWidth(65)
        row("Key delay (s)", self.key_delay)

        self.s3_wait = QLineEdit("6.0")
        self.s3_wait.setMaximumWidth(65)
        row("S3 wait (s)", self.s3_wait, "(UDS-14)")

        self.capture_window = QLineEdit("1.0")
        self.capture_window.setMaximumWidth(65)
        row("Capture window (s)", self.capture_window, "(UDS-19)")

        self.penalty_probe_delay = QLineEdit("0.05")
        self.penalty_probe_delay.setMaximumWidth(65)
        row("Penalty probe delay (s)", self.penalty_probe_delay, "(UDS-18)")

        sep("Behavior")
        self.preset = QComboBox()
        self.preset.addItems(["testcase", "unlock-check"])
        row("Preset", self.preset)

        chk_row("Strict session", "strict_session_chk")
        chk_row("Stop on positive unlock", "stop_on_positive_unlock_chk")
        chk_row("No summary", "no_summary_chk")

        sep("Logging")
        chk_row("--show-process", "show_process_chk", default=True)
        chk_row("--show-can (TX frames)", "show_can_chk")
        chk_row("--verbose (raw RX)", "verbose_chk")

        return section

    # ------------------------------------------------------------------
    # Build target list
    # ------------------------------------------------------------------

    def _build_target_section(self) -> QGroupBox:
        grp = QGroupBox("Target List")
        layout = QVBoxLayout(grp)
        layout.setContentsMargins(6, 10, 6, 6)
        layout.setSpacing(4)

        hint = QLabel("Tip: editing Basic Config auto-syncs to selected row (or first row).")
        hint.setStyleSheet(f"color:{C_DIM}; font-size:10px;")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self.target_table = TargetTable(config_provider=self._target_config_from_basic)
        cfg = self._target_config_from_basic()
        self.target_table._make_row(**cfg)
        layout.addWidget(self.target_table)
        return grp

    # ------------------------------------------------------------------
    # Signal connections
    # ------------------------------------------------------------------

    def _connect_cmd_update(self):
        widgets = [
            self.channel, self.tx_id, self.rx_id, self.session_flow,
            self.seed_subfn, self.key_subfn, self.attempts,
            self.delay, self.timeout, self.key_hex, self.pattern_byte,
            self.interface, self.padding, self.fc_bs, self.fc_stmin,
            self.request_stmin, self.fc_wait_timeout, self.resp_pending_timeout,
            self.post_session_delay, self.key_delay, self.s3_wait,
            self.capture_window, self.penalty_probe_delay,
        ]
        for w in widgets:
            w.textChanged.connect(self._update_cmd_preview)
        for cb in [self.mode_combo, self.key_policy, self.preset]:
            cb.currentIndexChanged.connect(self._update_cmd_preview)
        for chk in [self.extended_id_chk, self.drain_before_run_chk,
                    self.strict_session_chk, self.stop_on_positive_unlock_chk,
                    self.no_summary_chk, self.show_process_chk,
                    self.show_can_chk, self.verbose_chk]:
            chk.toggled.connect(self._update_cmd_preview)

        for w in [self.tx_id, self.rx_id, self.session_flow, self.seed_subfn, self.attempts]:
            w.textChanged.connect(self._sync_config_to_target_list)
        self.mode_combo.currentIndexChanged.connect(self._sync_config_to_target_list)

        # Dashboard update
        for w in [self.tx_id, self.rx_id, self.session_flow, self.attempts]:
            w.textChanged.connect(self._update_dashboard_config)
        self.mode_combo.currentIndexChanged.connect(self._update_dashboard_config)

    def _update_dashboard_config(self):
        self.dashboard.update_config(
            tx=self.tx_id.text().strip() or "—",
            rx=self.rx_id.text().strip() or "—",
            mode=MODES[self.mode_combo.currentIndex()][0],
            session=self.session_flow.text().strip() or "—",
            attempts=self.attempts.text().strip() or "10",
        )

    # ------------------------------------------------------------------
    # Mode helpers
    # ------------------------------------------------------------------

    def _current_mode_value(self) -> str:
        return MODES[self.mode_combo.currentIndex()][1]

    def _on_mode_change(self):
        mode = self._current_mode_value()
        if mode in REPEATED_MODES:
            if self.attempts.text().strip() in ("1", ""):
                self.attempts.setText("10")
        else:
            if self.attempts.text().strip() == "10":
                self.attempts.setText("1")
        self._update_cmd_preview()

    def _on_seed_subfn_change(self, text: str):
        try:
            seed = int(text.strip(), 16)
            self.key_subfn.setText(f"{(seed + 1) & 0xFF:02X}")
        except ValueError:
            pass

    def _update_key_policy_ui(self):
        policy = self.key_policy.currentText()
        show_hex = policy == "explicit"
        show_pattern = policy == "pattern"

        for i in range(self.key_hex_row.count()):
            w = self.key_hex_row.itemAt(i).widget()
            if w:
                w.setVisible(show_hex)
        for i in range(self.pattern_byte_row.count()):
            w = self.pattern_byte_row.itemAt(i).widget()
            if w:
                w.setVisible(show_pattern)

        self._update_cmd_preview()

    # ------------------------------------------------------------------
    # Build CLI args (unchanged logic)
    # ------------------------------------------------------------------

    def _build_args(self, target: Optional[dict] = None) -> List[str]:
        t = target or {}
        channel  = self.channel.text().strip() or "can0"
        tx_id    = t.get("tx") or self.tx_id.text().strip()
        rx_id    = t.get("rx") or self.rx_id.text().strip()
        session  = t.get("session") or self.session_flow.text().strip() or "03"
        seed     = t.get("seed") or self.seed_subfn.text().strip()
        mode_val = t.get("mode") or self._current_mode_value()
        attempts = t.get("attempts") or self.attempts.text().strip()
        key_subfn = self.key_subfn.text().strip()
        if target and t.get("seed"):
            key_subfn = self._derive_key_subfn_from_seed(seed, key_subfn)

        args = [
            "--channel", channel,
            "--src", f"0x{tx_id.lstrip('0x').lstrip('0X') or '0'}",
            "--dst", f"0x{rx_id.lstrip('0x').lstrip('0X') or '0'}",
            "--mode", mode_val,
            "--session-flow", session,
            "--seed-subfn", seed,
            "--key-subfn", key_subfn,
            "--attempts", attempts,
            "--delay", self.delay.text().strip() or "0.2",
            "--timeout", self.timeout.text().strip() or "1.0",
            "--interface", self.interface.text().strip() or "socketcan",
            "--padding", self.padding.text().strip() or "00",
            "--fc-bs", self.fc_bs.text().strip() or "00",
            "--fc-stmin", self.fc_stmin.text().strip() or "00",
            "--request-stmin", self.request_stmin.text().strip() or "0.0",
            "--fc-wait-timeout", self.fc_wait_timeout.text().strip() or "3.0",
            "--response-pending-timeout", self.resp_pending_timeout.text().strip() or "5.0",
            "--post-session-delay", self.post_session_delay.text().strip() or "0.05",
            "--key-delay", self.key_delay.text().strip() or "0.05",
        ]

        policy = self.key_policy.currentText()
        args += ["--key-policy", policy]

        if policy == "explicit":
            kh = self.key_hex.text().strip()
            if kh:
                args += ["--key-hex", kh]
        elif policy == "pattern":
            pb = self.pattern_byte.text().strip() or "AA"
            args += ["--pattern-byte", pb]

        mode_val_eff = t.get("mode") or self._current_mode_value()
        if mode_val_eff == "seed-timeout-key":
            args += ["--s3-wait", self.s3_wait.text().strip() or "6.0"]
        if mode_val_eff == "multi-seed-response":
            args += ["--capture-window", self.capture_window.text().strip() or "1.0"]
        if mode_val_eff == "penalty-then-seed":
            args += ["--penalty-probe-delay", self.penalty_probe_delay.text().strip() or "0.05"]

        args += ["--preset", self.preset.currentText()]

        if self.extended_id_chk.isChecked():
            args.append("--extended-id")
        if self.drain_before_run_chk.isChecked():
            args.append("--drain-before-run")
        if self.strict_session_chk.isChecked():
            args.append("--strict-session")
        if self.stop_on_positive_unlock_chk.isChecked():
            args.append("--stop-on-positive-unlock")
        else:
            args.append("--no-stop-on-positive-unlock")
        if self.no_summary_chk.isChecked():
            args.append("--no-summary")
        if self.show_process_chk.isChecked():
            args.append("--show-process")
        if self.show_can_chk.isChecked():
            args.append("--show-can")
        if self.verbose_chk.isChecked():
            args.append("--verbose")

        return args

    def _update_cmd_preview(self):
        try:
            args = self._build_args()
            cmd = f"python3 {SCRIPT_NAME} " + " ".join(args)
            self.cmd_preview.setText(cmd)
        except Exception:
            pass

    def _copy_cmd(self):
        QApplication.clipboard().setText(self.cmd_preview.text())

    def _clear_logs(self):
        self.log_panel.clear()
        self.dashboard.can_error_card.setVisible(False)

    # ------------------------------------------------------------------
    # PoC Report export
    # ------------------------------------------------------------------

    def _save_poc_report(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PoC Report", f"poc_report_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt",
            "Text (*.txt);;JSON (*.json)"
        )
        if not path:
            return

        ts = datetime.datetime.now().isoformat()
        cfg = {
            "channel":   self.channel.text().strip(),
            "tx_id":     self.tx_id.text().strip(),
            "rx_id":     self.rx_id.text().strip(),
            "mode":      MODES[self.mode_combo.currentIndex()][0],
            "session":   self.session_flow.text().strip(),
            "seed_subfn":self.seed_subfn.text().strip(),
            "key_subfn": self.key_subfn.text().strip(),
            "attempts":  self.attempts.text().strip(),
            "key_policy":self.key_policy.currentText(),
        }

        timeline_text = self.log_panel.timeline.view.toPlainText()
        detailed_text = self.log_panel.log_view.toPlainText()

        if path.endswith(".json"):
            report = {
                "timestamp": ts,
                "config": cfg,
                "timeline": timeline_text,
                "detailed_log": detailed_text,
            }
            with open(path, "w") as f:
                json.dump(report, f, indent=2)
        else:
            with open(path, "w") as f:
                f.write(f"UDS-27 SecurityAccess Probe  –  PoC Report\n")
                f.write(f"Generated: {ts}\n")
                f.write("=" * 60 + "\n\n")
                f.write("CONFIGURATION\n")
                f.write("-" * 40 + "\n")
                for k, v in cfg.items():
                    f.write(f"  {k:20s}: {v}\n")
                f.write("\n")
                f.write("TIMELINE\n")
                f.write("-" * 40 + "\n")
                f.write(timeline_text)
                f.write("\n\n")
                f.write("DETAILED LOG\n")
                f.write("-" * 40 + "\n")
                f.write(detailed_text)
                f.write("\n\n")
                f.write("RAW CAN\n")
                f.write("-" * 40 + "\n")
                f.write(self.log_panel.raw_view.toPlainText())

    # ------------------------------------------------------------------
    # Config helpers
    # ------------------------------------------------------------------

    def _target_config_from_basic(self) -> dict:
        tx = self.tx_id.text().strip() or "681"
        rx = self.rx_id.text().strip() or "601"
        return {
            "enabled": True,
            "name": f"{tx}→{rx}",
            "tx": tx,
            "rx": rx,
            "session": self.session_flow.text().strip() or "03",
            "seed": self.seed_subfn.text().strip() or "01",
            "mode": self._current_mode_value(),
            "attempts": self.attempts.text().strip() or "1",
        }

    def _sync_config_to_target_list(self):
        if hasattr(self, "target_table"):
            self.target_table.sync_from_config(self._target_config_from_basic())

    @staticmethod
    def _derive_key_subfn_from_seed(seed: str, fallback: str) -> str:
        try:
            return f"{(int(seed.strip(), 16) + 1) & 0xFF:02X}"
        except ValueError:
            return fallback

    # ------------------------------------------------------------------
    # Validation (unchanged)
    # ------------------------------------------------------------------

    def _validate(self, target: Optional[dict] = None) -> Optional[str]:
        tx = (target or {}).get("tx") or self.tx_id.text().strip()
        rx = (target or {}).get("rx") or self.rx_id.text().strip()

        if not is_valid_hex_id(tx):
            return f"Invalid TX CAN ID: '{tx}'"
        if not is_valid_hex_id(rx):
            return f"Invalid RX CAN ID: '{rx}'"

        if not self.extended_id_chk.isChecked():
            try:
                if hex_to_int(tx) > 0x7FF:
                    return f"TX CAN ID {tx} > 0x7FF; enable Extended ID for 29-bit"
                if hex_to_int(rx) > 0x7FF:
                    return f"RX CAN ID {rx} > 0x7FF; enable Extended ID for 29-bit"
            except ValueError:
                pass

        seed = (target or {}).get("seed") or self.seed_subfn.text().strip()
        if not validate_byte_hex(seed):
            return f"RequestSeed subfn must be a valid byte hex: '{seed}'"

        key_sf = self.key_subfn.text().strip()
        if target and (target or {}).get("seed"):
            key_sf = self._derive_key_subfn_from_seed(seed, key_sf)
        if not validate_byte_hex(key_sf):
            return f"SendKey subfn must be a valid byte hex: '{key_sf}'"

        try:
            att = int((target or {}).get("attempts") or self.attempts.text().strip())
            if att <= 0:
                return "Attempts must be > 0"
        except ValueError:
            return "Attempts must be an integer"

        policy = self.key_policy.currentText()
        if policy == "explicit":
            kh = self.key_hex.text().strip().replace(" ", "").replace(":", "")
            if not kh:
                return "Explicit key hex is empty"
            try:
                bytes.fromhex(kh)
            except ValueError:
                return f"Explicit key hex is not valid hex: '{kh}'"
        if policy == "pattern":
            pb = self.pattern_byte.text().strip()
            if not validate_byte_hex(pb):
                return f"Pattern byte must be a valid hex byte: '{pb}'"

        return None

    # ------------------------------------------------------------------
    # Run logic (unchanged)
    # ------------------------------------------------------------------

    def _run_current(self):
        err = self._validate()
        if err:
            QMessageBox.warning(self, "Validation error", err)
            return
        name = self.tx_id.text().strip() + "→" + self.rx_id.text().strip()
        self._start_queue([{"name": name}])

    def _run_selected(self):
        rows = self.target_table.selected_rows()
        if not rows:
            QMessageBox.information(self, "No selection", "Select rows in the target list first.")
            return
        self._start_queue(rows)

    def _run_all_enabled(self):
        rows = [r for r in self.target_table.rows() if r["enabled"]]
        if not rows:
            QMessageBox.information(self, "No targets", "No enabled targets in the list.")
            return
        self._start_queue(rows)

    def _start_queue(self, targets: List[dict]):
        for t in targets:
            err = self._validate(t if t.get("tx") else None)
            if err:
                QMessageBox.warning(self, f"Validation error [{t.get('name','')}]", err)
                return

        self._queue = targets.copy()
        self.run_btn.setEnabled(False)
        self.run_sel_btn.setEnabled(False)
        self.run_all_btn.setEnabled(False)
        self.reset_ecu_btn.setEnabled(False)
        self.reset_all_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.dashboard.reset()
        self._update_dashboard_config()
        self._run_next()

    def _run_next(self):
        if not self._queue:
            self._on_all_done()
            return

        target = self._queue.pop(0)
        self._running_target = target
        name = target.get("name", "target")
        self.log_panel.set_target(name)
        self.log_panel.append_line(f"══ START  {name}  ══")

        script_path = self._find_script()
        if not script_path:
            self.log_panel.append_line(f"ERROR: {SCRIPT_NAME} not found next to uds27_gui.py")
            self._on_all_done()
            return

        args = self._build_args(target if target.get("tx") else None)

        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.MergedChannels)
        self._process.readyReadStandardOutput.connect(self._on_output)
        self._process.finished.connect(self._on_process_finished)
        self._process.start(sys.executable, [str(script_path)] + args)
        self._summary_buf.clear()
        self._in_summary = False

    def _find_script(self) -> Optional[Path]:
        candidates = [
            Path(__file__).parent / SCRIPT_NAME,
            Path.cwd() / SCRIPT_NAME,
        ]
        for p in candidates:
            if p.exists():
                return p
        return None

    def _on_output(self):
        if not self._process:
            return
        raw = bytes(self._process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.log_panel.append_raw(raw)

        for line in raw.splitlines():
            line = line.rstrip()
            # Dashboard processing (all lines)
            self.dashboard.process_line(line)

            if "RESULT" in line.upper() or "VERDICT" in line.upper():
                self._in_summary = True
            if self._in_summary:
                self._summary_buf.append(line)
            else:
                self.log_panel.append_line(line)

    def _on_process_finished(self, exit_code: int, exit_status):
        if self._summary_buf:
            self.log_panel.append_summary_block("\n".join(self._summary_buf))
            self._summary_buf.clear()
            self._in_summary = False

        name = self._running_target.get("name", "target") if self._running_target else "?"
        self.log_panel.append_line(f"══ DONE  {name}  rc={exit_code} ══")
        self._running_target = None
        QTimer.singleShot(300, self._run_next)

    def _stop(self):
        self._queue.clear()
        if self._process and self._process.state() != QProcess.NotRunning:
            self._process.kill()
        self._on_all_done()
        self.dashboard.verdict_card.set_verdict("STOPPED", "Run cancelled by operator")

    def _on_all_done(self):
        self.run_btn.setEnabled(True)
        self.run_sel_btn.setEnabled(True)
        self.run_all_btn.setEnabled(True)
        self.reset_ecu_btn.setEnabled(True)
        self.reset_all_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._running_target = None

    # ------------------------------------------------------------------
    # Direct UDS reset helpers (unchanged logic)
    # ------------------------------------------------------------------

    def _parse_padding_byte(self) -> int:
        text = self.padding.text().strip() or "00"
        try:
            value = int(text, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid padding byte: {text}") from exc
        if not 0 <= value <= 0xFF:
            raise ValueError(f"Padding byte out of range: {text}")
        return value

    def _uds_reset_payload(self) -> bytes:
        pad = self._parse_padding_byte()
        payload = bytes([0x02, 0x11, 0x01])
        return payload + bytes([pad] * (8 - len(payload)))

    def _process_is_running(self) -> bool:
        return bool(self._process and self._process.state() != QProcess.NotRunning)

    def _hard_reset_current_ecu(self):
        if self._process_is_running():
            QMessageBox.warning(self, "Run active", "Stop the current run before sending ECUReset.")
            return

        tx = self.tx_id.text().strip()
        rx = self.rx_id.text().strip()
        if not is_valid_hex_id(tx):
            QMessageBox.warning(self, "Validation error", f"Invalid Tester TX ID: '{tx}'")
            return
        if not is_valid_hex_id(rx):
            QMessageBox.warning(self, "Validation error", f"Invalid ECU Resp ID: '{rx}'")
            return

        tx_int = hex_to_int(tx)
        rx_int = hex_to_int(rx)
        if not self.extended_id_chk.isChecked() and (tx_int > 0x7FF or rx_int > 0x7FF):
            QMessageBox.warning(self, "Validation error", "CAN ID > 0x7FF; enable Extended ID for 29-bit IDs.")
            return

        answer = QMessageBox.question(
            self, "Confirm hard reset",
            f"Send UDS ECUReset hardReset (11 01) to ECU 0x{tx_int:X}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self._send_hard_reset(tx_int, wait_rxid=rx_int, label=f"ECU 0x{tx_int:X}→0x{rx_int:X}")

    def _hard_reset_broadcast(self):
        if self._process_is_running():
            QMessageBox.warning(self, "Run active", "Stop the current run before sending broadcast ECUReset.")
            return

        bcast_id = 0x6FF
        answer = QMessageBox.question(
            self, "Confirm broadcast hard reset",
            "Send UDS ECUReset hardReset (11 01) to broadcast Arbitration ID 0x6FF?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        self._send_hard_reset(bcast_id, wait_rxid=None, label="BROADCAST 0x6FF")

    def _send_hard_reset(self, txid: int, *, wait_rxid: Optional[int], label: str):
        try:
            can_module = __import__("can")
        except ImportError:
            QMessageBox.critical(self, "Missing dependency", "Missing python-can. Install with: pip install python-can")
            return

        try:
            payload = self._uds_reset_payload()
        except ValueError as exc:
            QMessageBox.warning(self, "Validation error", str(exc))
            return

        channel = self.channel.text().strip() or "can0"
        interface = self.interface.text().strip() or "socketcan"
        extended = self.extended_id_chk.isChecked()
        timeout_s = 0.8
        try:
            timeout_s = max(0.1, float(self.timeout.text().strip() or "1.0"))
        except ValueError:
            pass

        self.log_panel.set_target(label)
        self.log_panel.append_line(f"RESET TX  {txid:X}# {bhex(payload)}  UDS 11 01 hardReset")

        bus = None
        try:
            try:
                bus = can_module.interface.Bus(channel=channel, interface=interface)
            except TypeError:
                bus = can_module.interface.Bus(channel=channel, bustype=interface)

            msg = can_module.Message(arbitration_id=txid, data=payload, is_extended_id=extended)
            bus.send(msg)

            if wait_rxid is None:
                self.log_panel.append_line("RESET BROADCAST sent; no response expected")
                return

            import time as _time
            end = _time.monotonic() + timeout_s
            while _time.monotonic() < end:
                remaining = max(0.0, end - _time.monotonic())
                rx = bus.recv(timeout=remaining)
                if rx is None:
                    break
                data = bytes(rx.data)
                if rx.arbitration_id != wait_rxid:
                    continue
                desc = self._describe_reset_response(data)
                self.log_panel.append_line(f"RESET RX  {rx.arbitration_id:X}# {bhex(data)}  {desc}")
                return

            self.log_panel.append_line(f"RESET RX  timeout waiting 0x{wait_rxid:X}")

        except Exception as exc:
            self.log_panel.append_line(f"ERROR reset failed: {type(exc).__name__}: {exc}")
            self.dashboard.can_error_card.show_error(str(exc))
            QMessageBox.critical(self, "Reset failed", f"{type(exc).__name__}: {exc}")
        finally:
            if bus is not None:
                try:
                    bus.shutdown()
                except Exception:
                    pass

    @staticmethod
    def _describe_reset_response(data: bytes) -> str:
        if len(data) >= 3 and data[0] == 0x02 and data[1] == 0x51 and data[2] == 0x01:
            return "POS 51 01 hardReset"
        if len(data) >= 4 and data[0] == 0x03 and data[1] == 0x7F and data[2] == 0x11:
            nrc = data[3]
            info = NRC_MEANINGS.get(nrc)
            return f"NRC {nrc:02X} {info[0] if info else 'unknownNRC'}"
        return "RX raw"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE_SHEET)
    app.setApplicationName("UDS-27 SecurityAccess Probe")

    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
