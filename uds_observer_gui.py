#!/usr/bin/env python3
"""
UDS Observer Toolkit GUI

Single GUI entry point for the config-driven UDS observer toolkit.
Run:
    python3 uds_observer_gui.py
"""
from __future__ import annotations

import copy
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

try:
    import yaml
except ImportError as exc:  # pragma: no cover - startup guard
    print("Missing dependency: PyYAML. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc

try:
    from PySide6.QtCore import QEvent, QProcess, QProcessEnvironment, Qt, QUrl
    from PySide6.QtGui import QColor, QDesktopServices, QFont, QTextCharFormat, QTextCursor
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFileDialog,
        QFormLayout,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QListWidget,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QScrollArea,
        QSplitter,
        QTabWidget,
        QTextEdit,
        QVBoxLayout,
        QWidget,
)
except ImportError as exc:  # pragma: no cover - startup guard
    print("Missing dependency: PySide6. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc

from uds_toolkit.testcase_ui_schema import (
    ValidationMessage,
    build_effective_config,
    format_effective_config_preview,
    get_ui_schema_for_testcase,
    validate_effective_config,
)
from uds_toolkit.testcase_metadata import normalize_testcase_metadata, sort_testcases_by_report_order


APP_TITLE = "UDS Observer Toolkit"
ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_FILES = [
    ROOT / "configs" / "default.yaml",
    ROOT / "testcases" / "security_access.yaml",
    ROOT / "testcases" / "seed_sampling.yaml",
    ROOT / "testcases" / "fuzzing_basic.yaml",
    ROOT / "testcases" / "uds_section10_access_control.yaml",
]

CATEGORIES = ["All", "Reconnaissance", "SecurityAccess", "Seed Sampling", "Access Control", "Fuzzing"]
GROUPS = ["All", "Group A", "Group B", "Group C", "Group D", "Section 10", "Recon"]

STYLE = """
QWidget {
    background: #12161c;
    color: #d7dde7;
    font-family: Consolas, "JetBrains Mono", monospace;
    font-size: 12px;
}
QScrollArea {
    border: none;
    background: #12161c;
}
QGroupBox {
    border: 1px solid #2a3340;
    border-radius: 6px;
    margin-top: 8px;
    padding: 7px;
    background: #171c24;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #7db3ff;
    font-weight: bold;
}
QLineEdit, QComboBox, QListWidget, QTextEdit {
    background: #0b0f14;
    border: 1px solid #2a3340;
    border-radius: 4px;
    color: #d7dde7;
    selection-background-color: #1f4f86;
}
QLineEdit, QComboBox {
    padding: 4px 6px;
}
QTextEdit {
    padding: 6px;
    font-size: 14px;
}
QPushButton {
    background: #202938;
    border: 1px solid #39465a;
    border-radius: 4px;
    padding: 6px 10px;
    color: #d7dde7;
}
QPushButton:hover { background: #2b5f9e; }
QPushButton:disabled { color: #697386; background: #141922; }
QPushButton#runButton { background: #10351f; border-color: #2f8f53; color: #81e6a5; font-weight: bold; }
QPushButton#stopButton { background: #3a1111; border-color: #8f2f2f; color: #ff9c9c; font-weight: bold; }
QCheckBox { spacing: 6px; }
QSplitter::handle { background: #2a3340; }
QTabWidget::pane { border: 1px solid #2a3340; background: #0b0f14; }
QTabBar::tab {
    background: #1c2430;
    color: #9ba7b8;
    padding: 7px 10px;
    border: 1px solid #2a3340;
}
QTabBar::tab:selected { color: #d7dde7; background: #243044; }
"""


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if key == "testcases" and isinstance(value, list):
            existing = out.get(key)
            if isinstance(existing, list):
                out[key] = copy.deepcopy(existing) + copy.deepcopy(value)
            else:
                out[key] = copy.deepcopy(value)
        elif isinstance(value, Mapping) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_config_files(paths: Iterable[Path]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for path in paths:
        merged = deep_merge(merged, load_yaml(path))
    return merged


def parse_hex_int(text: str) -> int:
    raw = str(text).strip().replace("_", "")
    if not raw:
        raise ValueError("empty hex value")
    return int(raw, 16)


def parse_byte_list(text: str) -> List[int]:
    raw = str(text or "").strip()
    if not raw:
        return []
    tokens = [t for t in re.split(r"[\s,;>\-]+", raw) if t]
    out = []
    for token in tokens:
        value = parse_hex_int(token)
        if not 0 <= value <= 0xFF:
            raise ValueError(f"session byte out of range: {token}")
        out.append(value)
    return out


def hex_text(value: Any, width: int = 2) -> str:
    if value is None:
        return ""
    try:
        n = int(str(value), 16) if isinstance(value, str) else int(value)
    except Exception:
        return str(value)
    return f"0x{n:0{width}X}"


def display_path(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def session_text(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value
    try:
        return " ".join(f"{int(v):02X}" for v in value)
    except Exception:
        return str(value)


class UdsObserverGui(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setWindowFlags(
            self.windowFlags()
            | Qt.WindowType.WindowMinimizeButtonHint
            | Qt.WindowType.WindowMaximizeButtonHint
        )
        self.setMinimumSize(980, 640)
        self.resize_to_screen()
        self.config_files: List[Path] = [p for p in DEFAULT_CONFIG_FILES if p.exists()]
        self.config: Dict[str, Any] = {}
        self.all_cases: List[Dict[str, Any]] = []
        self.filtered_cases: List[Dict[str, Any]] = []
        self.current_case_key: str = ""
        self.testcase_overrides: Dict[str, Dict[str, Any]] = {}
        self.param_widgets: Dict[str, QWidget] = {}
        self.param_rows: Dict[str, QWidget] = {}
        self.param_row_layouts: Dict[str, QFormLayout] = {}
        self.current_validation: List[ValidationMessage] = []
        self._updating_ui = False
        self.process: Optional[QProcess] = None
        self.can_config_process: Optional[QProcess] = None
        self.last_log_dir: Optional[Path] = None
        self._build_ui()
        self.reload_config_and_cases()

    def resize_to_screen(self) -> None:
        screen = QApplication.primaryScreen()
        if not screen:
            self.resize(1280, 760)
            return
        available = screen.availableGeometry()
        width = min(1360, max(980, int(available.width() * 0.92)))
        height = min(820, max(640, int(available.height() * 0.88)))
        self.resize(width, height)
        frame = self.frameGeometry()
        frame.moveCenter(available.center())
        self.move(frame.topLeft())

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(10, 8, 10, 10)
        main.setSpacing(8)

        header = QHBoxLayout()
        title = QLabel("UDS Observer Toolkit")
        title.setFont(QFont("Consolas", 14, QFont.Weight.Bold))
        subtitle = QLabel("official UDS testcase workflow / evidence-focused runner")
        subtitle.setStyleSheet("color:#8b96a8")
        subtitle.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        header.addWidget(title)
        header.addWidget(subtitle)
        header.addStretch(1)
        self.maximize_btn = QPushButton("Maximize")
        self.maximize_btn.setToolTip("Toggle maximized window size.")
        self.fullscreen_btn = QPushButton("Full screen")
        self.fullscreen_btn.setToolTip("Toggle borderless full screen (F11). Press Esc to leave full screen.")
        header.addWidget(self.maximize_btn)
        header.addWidget(self.fullscreen_btn)
        main.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        left.setMinimumWidth(360)
        left.setMaximumWidth(560)
        splitter.addWidget(left)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        left_scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        left_layout.addWidget(left_scroll, 1)

        left_body = QWidget()
        left_body_layout = QVBoxLayout(left_body)
        left_body_layout.setContentsMargins(0, 0, 6, 0)
        left_body_layout.setSpacing(8)
        left_scroll.setWidget(left_body)

        target_group = QGroupBox("Target Profile")
        target_layout = QFormLayout(target_group)
        target_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        self.channel_edit = QLineEdit("can0")
        self.interface_edit = QLineEdit("socketcan")
        self.target_combo = QComboBox()
        self.txid_edit = QLineEdit("0x681")
        self.rxid_edit = QLineEdit("0x601")
        self.padding_edit = QLineEdit("0x00")
        self.timeout_edit = QLineEdit("1.0")
        self.rp_timeout_edit = QLineEdit("5.0")
        self.extended_check = QCheckBox("29-bit extended CAN ID")
        target_layout.addRow("Target profile", self.target_combo)
        target_layout.addRow("Channel", self.channel_edit)
        target_layout.addRow("TX ID", self.txid_edit)
        target_layout.addRow("RX ID", self.rxid_edit)
        target_buttons = QHBoxLayout()
        self.reset_target_btn = QPushButton("Reset target")
        self.configure_can_btn = QPushButton("Configure CAN")
        self.check_can_btn = QPushButton("Check CAN")
        target_buttons.addWidget(self.reset_target_btn)
        target_buttons.addWidget(self.configure_can_btn)
        target_buttons.addWidget(self.check_can_btn)
        target_layout.addRow("", target_buttons)
        left_body_layout.addWidget(target_group)

        self.advanced_target_group = QGroupBox("Advanced Target")
        self.advanced_target_group.setCheckable(True)
        self.advanced_target_group.setChecked(False)
        advanced_target_layout = QFormLayout(self.advanced_target_group)
        advanced_target_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        advanced_target_layout.addRow("Interface", self.interface_edit)
        advanced_target_layout.addRow("Padding byte", self.padding_edit)
        advanced_target_layout.addRow("Timeout", self.timeout_edit)
        advanced_target_layout.addRow("ResponsePending timeout", self.rp_timeout_edit)
        advanced_target_layout.addRow("", self.extended_check)
        left_body_layout.addWidget(self.advanced_target_group)

        selector_group = QGroupBox("Testcase")
        selector_layout = QVBoxLayout(selector_group)
        self.category_filter = QComboBox()
        self.category_filter.addItems(CATEGORIES)
        self.group_filter = QComboBox()
        self.group_filter.addItems(GROUPS)
        for label, widget in (("Category", self.category_filter), ("Group", self.group_filter)):
            row = QHBoxLayout()
            row.addWidget(QLabel(label), 0)
            row.addWidget(widget, 1)
            selector_layout.addLayout(row)
        self.testcase_combo = QComboBox()
        selector_layout.addWidget(self.testcase_combo)
        self.summary_id_label = QLabel("Test ID: -")
        self.summary_title_label = QLabel("Title: -")
        self.summary_type_label = QLabel("Type / mode: -")
        self.summary_service_label = QLabel("Service: -")
        self.summary_safety_label = QLabel("Flow: TX/RX observe")
        self.summary_objective_label = QLabel("Objective: -")
        for label in (
            self.summary_id_label,
            self.summary_title_label,
            self.summary_type_label,
            self.summary_service_label,
            self.summary_safety_label,
            self.summary_objective_label,
        ):
            label.setWordWrap(True)
            selector_layout.addWidget(label)
        left_body_layout.addWidget(selector_group)

        self.parameters_group = QGroupBox("Testcase Parameters")
        self.parameters_layout = QFormLayout(self.parameters_group)
        self.parameters_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        left_body_layout.addWidget(self.parameters_group)
        self.reset_overrides_btn = QPushButton("Reset testcase overrides")
        left_body_layout.addWidget(self.reset_overrides_btn)

        self.advanced_params_group = QGroupBox("Advanced Parameters")
        self.advanced_params_group.setCheckable(True)
        self.advanced_params_group.setChecked(False)
        self.advanced_params_layout = QFormLayout(self.advanced_params_group)
        self.advanced_params_layout.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        left_body_layout.addWidget(self.advanced_params_group)

        safety_group = QGroupBox("Run / Observe")
        safety_layout = QVBoxLayout(safety_group)
        self.safety_badge = QLabel("Mode: transmit and observe")
        self.safety_badge.setStyleSheet("color:#81e6a5; font-weight:bold;")
        self.dry_run_check = QCheckBox("Dry run / validate only")
        self.dry_run_check.setChecked(False)
        self.authorized_check = QCheckBox("I am authorized")
        self.authorized_check.setChecked(True)
        self.destructive_confirm_check = QCheckBox("Destructive confirm")
        self.destructive_confirm_check.setChecked(True)
        self.destructive_confirm_check.setVisible(False)
        self.show_process_check = QCheckBox("Show process steps")
        self.show_process_check.setChecked(True)
        self.show_can_check = QCheckBox("Show CAN TX")
        self.show_can_check.setChecked(True)
        self.verbose_check = QCheckBox("Verbose RX/debug")
        self.verbose_check.setChecked(True)
        for widget in (
            self.safety_badge,
            self.show_process_check,
            self.show_can_check,
            self.verbose_check,
        ):
            safety_layout.addWidget(widget)
        left_body_layout.addWidget(safety_group)

        effective_group = QGroupBox("Effective")
        effective_layout = QVBoxLayout(effective_group)
        self.effective_status = QLabel("Effective: -")
        self.effective_status.setWordWrap(True)
        effective_layout.addWidget(self.effective_status)
        self.validation_view = QLabel("")
        self.validation_view.setWordWrap(True)
        effective_layout.addWidget(self.validation_view)
        left_body_layout.addWidget(effective_group)

        self.advanced_yaml_group = QGroupBox("Advanced YAML Management")
        self.advanced_yaml_group.setCheckable(True)
        self.advanced_yaml_group.setChecked(False)
        yaml_layout = QVBoxLayout(self.advanced_yaml_group)
        self.config_list = QListWidget()
        self.config_list.setMinimumHeight(64)
        self.config_list.setMaximumHeight(112)
        yaml_layout.addWidget(self.config_list)
        cfg_btns = QHBoxLayout()
        self.add_cfg_btn = QPushButton("Add YAML")
        self.remove_cfg_btn = QPushButton("Remove")
        self.reload_btn = QPushButton("Reload")
        cfg_btns.addWidget(self.add_cfg_btn)
        cfg_btns.addWidget(self.remove_cfg_btn)
        cfg_btns.addWidget(self.reload_btn)
        yaml_layout.addLayout(cfg_btns)
        left_body_layout.addWidget(self.advanced_yaml_group)
        left_body_layout.addStretch(1)

        run_row = QHBoxLayout()
        self.run_selected_btn = QPushButton("Run selected")
        self.run_selected_btn.setObjectName("runButton")
        self.run_all_btn = QPushButton("Run visible")
        self.run_all_btn.setObjectName("runButton")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setObjectName("stopButton")
        self.stop_btn.setEnabled(False)
        run_row.addWidget(self.run_selected_btn)
        run_row.addWidget(self.run_all_btn)
        run_row.addWidget(self.stop_btn)
        left_layout.addLayout(run_row)

        self.open_logs_btn = QPushButton("Open last log folder")
        self.open_logs_btn.setEnabled(False)
        left_layout.addWidget(self.open_logs_btn)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)
        right.setMinimumWidth(520)
        splitter.addWidget(right)
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        right_layout.addWidget(self.tabs, 1)

        self.live_log_view = self._make_log_view()
        self.can_view = self._make_log_view()
        self.verdict_view = self._make_log_view()
        self.evidence_view = self._make_log_view()
        self.tabs.addTab(self.live_log_view, "Live")
        self.tabs.addTab(self.can_view, "CAN TX/RX")
        self.tabs.addTab(self.verdict_view, "Verdicts")
        self.tabs.addTab(self.evidence_view, "Evidence")
        self.command_preview_view = self._make_log_view()
        self.tabs.addTab(self.command_preview_view, "Effective Config")

        log_buttons = QHBoxLayout()
        self.clear_log_btn = QPushButton("Clear evidence views")
        log_buttons.addWidget(self.clear_log_btn)
        log_buttons.addStretch(1)
        right_layout.addLayout(log_buttons)

        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([430, 930])

        self.maximize_btn.clicked.connect(self.toggle_maximized)
        self.fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        self.add_cfg_btn.clicked.connect(self.add_config_file)
        self.remove_cfg_btn.clicked.connect(self.remove_config_file)
        self.reload_btn.clicked.connect(self.reload_config_and_cases)
        self.target_combo.currentTextChanged.connect(self.on_target_changed)
        self.reset_target_btn.clicked.connect(lambda: self.populate_target_fields(self.target_combo.currentText()))
        self.configure_can_btn.clicked.connect(self.configure_can_interface)
        self.check_can_btn.clicked.connect(lambda: self.can_interface_is_up(show=True))
        for widget in (
            self.channel_edit,
            self.interface_edit,
            self.txid_edit,
            self.rxid_edit,
            self.padding_edit,
            self.timeout_edit,
            self.rp_timeout_edit,
        ):
            widget.textChanged.connect(self.update_effective_preview)
        self.extended_check.toggled.connect(self.update_effective_preview)
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        self.group_filter.currentTextChanged.connect(self.apply_filters)
        self.testcase_combo.currentIndexChanged.connect(self.on_testcase_changed)
        self.run_selected_btn.clicked.connect(lambda: self.start_run(selected_only=True))
        self.run_all_btn.clicked.connect(lambda: self.start_run(selected_only=False))
        self.stop_btn.clicked.connect(self.stop_process)
        self.open_logs_btn.clicked.connect(self.open_last_log_dir)
        self.clear_log_btn.clicked.connect(self.clear_evidence_views)
        self.reset_overrides_btn.clicked.connect(self.reset_testcase_overrides)
        self.dry_run_check.toggled.connect(self.update_effective_preview)
        self.authorized_check.toggled.connect(self.update_effective_preview)
        self.destructive_confirm_check.toggled.connect(self.update_effective_preview)
        self.advanced_yaml_group.toggled.connect(self.set_advanced_yaml_visible)
        self.advanced_params_group.toggled.connect(self.set_advanced_params_visible)
        self.advanced_target_group.toggled.connect(self.set_advanced_target_visible)
        self.set_advanced_target_visible(False)
        self.set_advanced_yaml_visible(False)
        self.set_advanced_params_visible(False)

    def _make_log_view(self) -> QTextEdit:
        view = QTextEdit()
        view.setReadOnly(True)
        view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        view.setFont(QFont("Consolas", 13))
        return view

    def set_advanced_yaml_visible(self, visible: bool) -> None:
        for child in self.advanced_yaml_group.findChildren(QWidget):
            if child is not self.advanced_yaml_group:
                child.setVisible(visible)

    def set_advanced_target_visible(self, visible: bool) -> None:
        for child in self.advanced_target_group.findChildren(QWidget):
            if child is not self.advanced_target_group:
                child.setVisible(visible)

    def set_advanced_params_visible(self, visible: bool) -> None:
        for child in self.advanced_params_group.findChildren(QWidget):
            if child is not self.advanced_params_group:
                child.setVisible(visible)

    def on_target_changed(self, target_name: str) -> None:
        self.populate_target_fields(target_name)
        self.update_effective_preview()

    def configure_can_interface(self) -> None:
        if self.can_config_process is not None:
            QMessageBox.information(self, "CAN config running", "CAN configuration is already running.")
            return
        script = ROOT / "can_config.sh"
        if not script.exists():
            QMessageBox.warning(self, "Missing can_config.sh", f"Cannot find {script}")
            return
        channel = self.channel_edit.text().strip() or "can0"
        self.append_log(f"\n$ bash {script} {channel}\n")
        self.can_config_process = QProcess(self)
        self.can_config_process.setWorkingDirectory(str(ROOT))
        self.can_config_process.readyReadStandardOutput.connect(self.read_can_config_stdout)
        self.can_config_process.readyReadStandardError.connect(self.read_can_config_stderr)
        self.can_config_process.finished.connect(self.can_config_finished)
        self.can_config_process.start("bash", [str(script), channel])
        if not self.can_config_process.waitForStarted(3000):
            self.append_log("Failed to start can_config.sh. Run it manually in a terminal.\n")
            self.can_config_process = None

    def read_can_config_stdout(self) -> None:
        if not self.can_config_process:
            return
        text = bytes(self.can_config_process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.append_log(text, raw=True)

    def read_can_config_stderr(self) -> None:
        if not self.can_config_process:
            return
        text = bytes(self.can_config_process.readAllStandardError()).decode("utf-8", errors="replace")
        self.append_log(text, raw=True)

    def can_config_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        status = "normal" if exit_status == QProcess.ExitStatus.NormalExit else "crashed"
        self.append_log(f"\n[can_config finished] exit_code={exit_code} status={status}\n")
        self.can_config_process = None
        self.can_interface_is_up(show=True)

    def can_interface_is_up(self, *, show: bool = False) -> bool:
        interface = self.interface_edit.text().strip() or "socketcan"
        if interface not in {"socketcan", "socketcan_native"}:
            return True
        channel = self.channel_edit.text().strip() or "can0"
        try:
            result = subprocess.run(
                ["ip", "-details", "link", "show", channel],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except FileNotFoundError:
            if show:
                self.append_log("Cannot check SocketCAN: missing Linux 'ip' command.\n")
            return False
        except subprocess.TimeoutExpired:
            if show:
                self.append_log(f"Timed out checking {channel}.\n")
            return False
        output = (result.stdout or result.stderr or "").strip()
        if show:
            self.append_log(f"\n$ ip -details link show {channel}\n{output}\n")
        if result.returncode != 0:
            return False
        first_line = output.splitlines()[0] if output else ""
        flags = first_line.split("<", 1)[1].split(">", 1)[0].split(",") if "<" in first_line and ">" in first_line else []
        return "UP" in flags

    def on_testcase_changed(self) -> None:
        if self._updating_ui:
            return
        self.save_current_overrides()
        self.current_case_key = self.case_key(self.current_testcase())
        self.rebuild_parameter_form()
        self.update_detail_card()
        self.update_effective_preview()

    def case_key(self, testcase: Mapping[str, Any]) -> str:
        if not testcase:
            return ""
        ids = testcase.get("test_ids") or []
        if ids:
            return "|".join(str(x) for x in ids)
        return str(testcase.get("internal_name") or testcase.get("name") or "")

    def clear_layout(self, layout: QFormLayout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            child_layout = item.layout()
            if widget is not None:
                widget.deleteLater()
            elif child_layout is not None:
                while child_layout.count():
                    child = child_layout.takeAt(0)
                    if child.widget() is not None:
                        child.widget().deleteLater()

    def rebuild_parameter_form(self) -> None:
        tc = self.current_testcase()
        self.param_widgets = {}
        self.param_rows = {}
        self.param_row_layouts = {}
        self.clear_layout(self.parameters_layout)
        self.clear_layout(self.advanced_params_layout)
        if not tc:
            return
        schema = get_ui_schema_for_testcase(tc)
        saved = self.testcase_overrides.get(self.case_key(tc), {})
        for field in schema.get("parameter_fields", []):
            self.add_parameter_row(self.parameters_layout, tc, field, saved)
        for field in schema.get("advanced_fields", []):
            self.add_parameter_row(self.advanced_params_layout, tc, field, saved)
        self.update_param_visibility()
        self.set_advanced_params_visible(self.advanced_params_group.isChecked())

    def add_parameter_row(self, layout: QFormLayout, tc: Mapping[str, Any], field: Mapping[str, Any], saved: Mapping[str, Any]) -> None:
        key = str(field.get("key"))
        value = saved.get(key, self.field_default_value(tc, field))
        widget = self.make_field_widget(field, value)
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.addWidget(widget)
        layout.addRow(str(field.get("label", key)), row)
        self.param_widgets[key] = widget
        self.param_rows[key] = row
        self.param_row_layouts[key] = layout
        help_text = str(field.get("help") or "")
        if help_text:
            widget.setToolTip(help_text)
        self.connect_param_widget(widget)

    def make_field_widget(self, field: Mapping[str, Any], value: Any) -> QWidget:
        field_type = str(field.get("type", "text"))
        if field_type == "bool":
            widget = QCheckBox()
            widget.setChecked(bool(value))
            return widget
        if field_type == "dropdown":
            widget = QComboBox()
            options = [str(x) for x in field.get("options", [])]
            widget.addItems(options)
            text = str(value if value is not None else field.get("default", ""))
            idx = widget.findText(text)
            if idx < 0 and options:
                idx = 0
            if idx >= 0:
                widget.setCurrentIndex(idx)
            return widget
        if field_type == "payload_list" and str(field.get("key")) == "payloads":
            widget = QTextEdit()
            widget.setMinimumHeight(72)
            widget.setPlainText("\n".join(str(x) for x in value) if isinstance(value, list) else str(value or ""))
            return widget
        widget = QLineEdit(self.value_to_text(value, field_type))
        return widget

    def connect_param_widget(self, widget: QWidget) -> None:
        if isinstance(widget, QCheckBox):
            widget.toggled.connect(self.on_parameter_edited)
        elif isinstance(widget, QComboBox):
            widget.currentTextChanged.connect(self.on_parameter_edited)
        elif isinstance(widget, QTextEdit):
            widget.textChanged.connect(self.on_parameter_edited)
        elif isinstance(widget, QLineEdit):
            widget.textChanged.connect(self.on_parameter_edited)

    def on_parameter_edited(self, *args: Any) -> None:
        if self._updating_ui:
            return
        self.save_current_overrides()
        self.update_param_visibility()
        self.update_effective_preview()

    def update_param_visibility(self) -> None:
        values = self.read_parameter_widgets()
        for key, row in self.param_rows.items():
            field = self.field_schema_by_key(key)
            conditions = field.get("visible_if") if field else {}
            visible = True
            for cond_key, expected in (conditions or {}).items():
                actual = values.get(str(cond_key))
                if isinstance(expected, list):
                    visible = visible and actual in expected
                else:
                    visible = visible and actual == expected
            row.setVisible(visible)
            layout = self.param_row_layouts.get(key)
            if layout is not None:
                layout.setRowVisible(row, visible)
        self.set_advanced_params_visible(self.advanced_params_group.isChecked())

    def field_schema_by_key(self, key: str) -> Dict[str, Any]:
        tc = self.current_testcase()
        schema = get_ui_schema_for_testcase(tc) if tc else {}
        for field in list(schema.get("parameter_fields", [])) + list(schema.get("advanced_fields", [])):
            if field.get("key") == key:
                return dict(field)
        return {}

    def field_default_value(self, tc: Mapping[str, Any], field: Mapping[str, Any]) -> Any:
        key = str(field.get("key"))
        if str(tc.get("type")) == "uds_access_control_probe":
            request = self.first_request(tc)
            if key in request:
                return request.get(key)
            if key == "payload":
                return request.get("payload", "")
        if str(tc.get("type")) == "arb_id_fuzzer":
            if key == "arb_id_start":
                return self.range_start(tc.get("txid_range"), field.get("default"))
            if key == "arb_id_end":
                return self.range_end(tc.get("txid_range"), field.get("default"))
        if str(tc.get("type")) == "service_fuzzer":
            if key == "service_start":
                return self.range_start(tc.get("services"), field.get("default"))
            if key == "service_end":
                return self.range_end(tc.get("services"), field.get("default"))
        if str(tc.get("type")) == "subservice_fuzzer":
            if key == "subservice_start":
                return self.range_start(tc.get("subfunctions"), field.get("default"))
            if key == "subservice_end":
                return self.range_end(tc.get("subfunctions"), field.get("default"))
        if str(tc.get("type")) == "seed_sampler_cross_session" and key == "session_boundary":
            flow = tc.get("boundary_session_flow")
            return "none" if flow in (None, "", []) else "default"
        if key in tc:
            return tc.get(key)
        return field.get("default")

    def first_request(self, tc: Mapping[str, Any]) -> Dict[str, Any]:
        requests = tc.get("requests") or []
        if isinstance(requests, list) and requests and isinstance(requests[0], Mapping):
            return copy.deepcopy(dict(requests[0]))
        return {}

    def range_start(self, value: Any, default: Any = "") -> str:
        text = str(value or "")
        return (text.split(",", 1)[0].split("-", 1)[0].strip() or str(default or ""))

    def range_end(self, value: Any, default: Any = "") -> str:
        text = str(value or "")
        first = text.split(",", 1)[0]
        if "-" in first:
            return first.split("-", 1)[1].strip()
        return str(default or "")

    def value_to_text(self, value: Any, field_type: str = "text") -> str:
        if value is None:
            return ""
        if field_type == "hex_list" and isinstance(value, list):
            return session_text(value)
        if field_type in {"hex_byte", "hex_id"} and isinstance(value, int):
            return hex_text(value, 3 if field_type == "hex_id" else 2)
        if isinstance(value, list):
            return ", ".join(str(x) for x in value)
        return str(value)

    def read_parameter_widgets(self) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for key, widget in self.param_widgets.items():
            field = self.field_schema_by_key(key)
            field_type = str(field.get("type", "text"))
            if isinstance(widget, QCheckBox):
                values[key] = bool(widget.isChecked())
            elif isinstance(widget, QComboBox):
                values[key] = widget.currentText()
            elif isinstance(widget, QTextEdit):
                text = widget.toPlainText().strip()
                values[key] = [line.strip() for line in text.splitlines() if line.strip()] if key == "payloads" else text
            elif isinstance(widget, QLineEdit):
                text = widget.text().strip()
                if field_type == "int" and text:
                    try:
                        values[key] = int(text, 10)
                    except ValueError:
                        values[key] = text
                elif field_type == "float" and text:
                    try:
                        values[key] = float(text)
                    except ValueError:
                        values[key] = text
                elif field_type == "hex_list" and text:
                    try:
                        values[key] = parse_byte_list(text)
                    except ValueError:
                        values[key] = text
                else:
                    values[key] = text
        return values

    def save_current_overrides(self) -> None:
        if not self.current_case_key or not self.param_widgets:
            return
        values = self.read_parameter_widgets()
        visible_values = {key: value for key, value in values.items() if self.param_rows.get(key) is None or self.param_rows[key].isVisible()}
        if self.destructive_confirm_check.isVisible():
            visible_values["destructive_confirm"] = bool(self.destructive_confirm_check.isChecked())
        self.testcase_overrides[self.current_case_key] = visible_values

    def target_profile_from_gui(self) -> Dict[str, Any]:
        return {
            "name": self.target_combo.currentText().strip() or str(self.config.get("default_target", "ecu1")),
            "channel": self.channel_edit.text().strip() or "can0",
            "interface": self.interface_edit.text().strip() or "socketcan",
            "txid": self.txid_edit.text().strip() or "0x7E0",
            "rxid": self.rxid_edit.text().strip() or "0x7E8",
            "extended_id": bool(self.extended_check.isChecked()),
            "padding": self.padding_edit.text().strip() or "0x00",
            "timeout": self.timeout_edit.text().strip() or "1.0",
            "response_pending_timeout": self.rp_timeout_edit.text().strip() or "5.0",
        }

    def overrides_for_testcase(self, tc: Mapping[str, Any], *, include_current: bool = False) -> Dict[str, Any]:
        key = self.case_key(tc)
        values = copy.deepcopy(self.testcase_overrides.get(key, {}))
        if include_current and key == self.current_case_key:
            values.update(self.read_parameter_widgets())
            if self.destructive_confirm_check.isVisible():
                values["destructive_confirm"] = bool(self.destructive_confirm_check.isChecked())
        values["_dry_run"] = bool(self.dry_run_check.isChecked())
        values["_authorized"] = True
        values["destructive_confirm"] = True
        return values

    def effective_config_for_testcase(self, tc: Mapping[str, Any], *, include_current: bool = False) -> Dict[str, Any]:
        return build_effective_config(
            self.config,
            self.target_profile_from_gui(),
            copy.deepcopy(dict(tc)),
            self.overrides_for_testcase(tc, include_current=include_current),
        )

    def update_effective_preview(self, *args: Any) -> None:
        if self._updating_ui:
            return
        tc = self.current_testcase()
        if not tc:
            self.effective_status.setText("Effective: -")
            self.command_preview_view.clear()
            self.run_selected_btn.setEnabled(False)
            return
        try:
            effective = self.effective_config_for_testcase(tc, include_current=True)
            self.current_validation = validate_effective_config(effective)
            preview = format_effective_config_preview(effective)
            self.effective_status.setText(self.compact_effective_status(effective))
            self.command_preview_view.setPlainText(self.full_effective_preview(effective, preview))
            self.update_safety_badge(effective)
            self.update_validation_view()
        except Exception as exc:
            self.current_validation = [ValidationMessage("error", "config", str(exc))]
            self.effective_status.setText(f"Effective: invalid ({exc})")
            self.command_preview_view.setPlainText(f"Invalid effective config:\n{exc}")
            self.update_validation_view()
        self.run_selected_btn.setEnabled(not any(msg.severity == "error" for msg in self.current_validation))

    def full_effective_preview(self, effective: Mapping[str, Any], summary: str) -> str:
        command = [sys.executable, str(ROOT / "run_udstk.py"), "-c", "<runtime_config>", "--runs-dir", str(ROOT / "runs")]
        if self.dry_run_check.isChecked():
            command.append("--dry-run")
        command.append("--yes-i-am-authorized")
        if self.show_process_check.isChecked():
            command.append("--show-process")
        if self.show_can_check.isChecked():
            command.append("--show-can")
        if self.verbose_check.isChecked():
            command.append("--verbose")
        cfg = copy.deepcopy(dict(effective))
        return (
            summary
            + "\n\nbackend_execution_preview:\n  "
            + " ".join(command)
            + "\n\nfull_merged_runtime_config:\n"
            + yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True)
        )

    def compact_effective_status(self, effective: Mapping[str, Any]) -> str:
        info = effective.get("_gui_effective") or {}
        params = info.get("effective_parameters") or {}
        dry_run = "dry-run" if info.get("dry_run") else "transmit"
        count = params.get("attempts", params.get("samples", params.get("max_items", "")))
        suffix = f" | {count} items" if count not in ("", None) else ""
        return (
            f"Effective: {info.get('test_id', '')} | {info.get('target', '')} | "
            f"{info.get('tx_id', '')} -> {info.get('rx_id', '')} | {dry_run}{suffix}"
        )

    def update_safety_badge(self, effective: Mapping[str, Any]) -> None:
        tc = (effective.get("testcases") or [{}])[0]
        dry_run = bool((effective.get("safety") or {}).get("dry_run", False))
        self.safety_badge.setText("Mode: dry-run only" if dry_run else "Mode: transmit and observe")
        self.destructive_confirm_check.setVisible(False)
        self.destructive_confirm_check.blockSignals(True)
        self.destructive_confirm_check.setChecked(True)
        self.destructive_confirm_check.blockSignals(False)

    def update_validation_view(self) -> None:
        if not self.current_validation:
            self.validation_view.setText("Validation: OK")
            self.validation_view.setStyleSheet("color:#81e6a5;")
            return
        lines = [f"{msg.severity.upper()}: {msg.field}: {msg.message}" for msg in self.current_validation]
        has_error = any(msg.severity == "error" for msg in self.current_validation)
        self.validation_view.setText("\n".join(lines))
        self.validation_view.setStyleSheet("color:#ff9c9c;" if has_error else "color:#ffd166;")

    def reset_testcase_overrides(self) -> None:
        key = self.case_key(self.current_testcase())
        if key:
            self.testcase_overrides.pop(key, None)
        self.rebuild_parameter_form()
        self.update_effective_preview()

    def keyPressEvent(self, event: Any) -> None:
        if event.key() == Qt.Key.Key_F11:
            self.toggle_fullscreen()
            event.accept()
            return
        if event.key() == Qt.Key.Key_Escape and self.isFullScreen():
            self.toggle_fullscreen()
            event.accept()
            return
        super().keyPressEvent(event)

    def toggle_fullscreen(self) -> None:
        if self.isFullScreen():
            self.showNormal()
            self.fullscreen_btn.setText("Full screen")
            self.sync_window_action_labels()
        else:
            self.showFullScreen()
            self.fullscreen_btn.setText("Exit full screen")

    def toggle_maximized(self) -> None:
        if self.isFullScreen():
            self.showNormal()
        if self.isMaximized():
            self.showNormal()
        else:
            self.showMaximized()
        self.sync_window_action_labels()

    def changeEvent(self, event: Any) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.WindowStateChange:
            self.sync_window_action_labels()

    def sync_window_action_labels(self) -> None:
        self.maximize_btn.setText("Restore" if self.isMaximized() else "Maximize")
        self.fullscreen_btn.setText("Exit full screen" if self.isFullScreen() else "Full screen")

    def add_config_file(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Add YAML config/testcase", str(ROOT), "YAML files (*.yaml *.yml)")
        for path in paths:
            p = Path(path)
            if p not in self.config_files:
                self.config_files.append(p)
        self.reload_config_and_cases()

    def remove_config_file(self) -> None:
        row = self.config_list.currentRow()
        if row >= 0:
            del self.config_files[row]
            self.reload_config_and_cases()

    def reload_config_and_cases(self) -> None:
        self.config_list.clear()
        for path in self.config_files:
            self.config_list.addItem(display_path(path))
        try:
            self.config = load_config_files(self.config_files)
        except Exception as exc:
            QMessageBox.critical(self, "Config error", str(exc))
            self.config = {}
            return
        self.populate_targets()
        self.populate_cases()
        self.append_log(f"Loaded {len(self.config_files)} config file(s), {len(self.all_cases)} testcase(s).")

    def populate_targets(self) -> None:
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        targets = self.config.get("targets") or {}
        for name in targets.keys():
            self.target_combo.addItem(str(name))
        default_target = str(self.config.get("default_target", ""))
        idx = self.target_combo.findText(default_target)
        if idx >= 0:
            self.target_combo.setCurrentIndex(idx)
        self.target_combo.blockSignals(False)
        can_cfg = self.config.get("can") or {}
        timing_cfg = self.config.get("timing") or {}
        self.channel_edit.setText(str(can_cfg.get("channel", "can0")))
        self.interface_edit.setText(str(can_cfg.get("interface", "socketcan")))
        self.padding_edit.setText(hex_text(can_cfg.get("padding", "0x00"), 2))
        self.timeout_edit.setText(str(timing_cfg.get("timeout", 1.0)))
        self.rp_timeout_edit.setText(str(timing_cfg.get("response_pending_timeout", 5.0)))
        self.extended_check.setChecked(bool(can_cfg.get("extended_id", False)))
        self.populate_target_fields(self.target_combo.currentText())

    def populate_target_fields(self, target_name: str) -> None:
        targets = self.config.get("targets") or {}
        target = targets.get(target_name) or {}
        self.txid_edit.blockSignals(True)
        self.rxid_edit.blockSignals(True)
        self.extended_check.blockSignals(True)
        self.txid_edit.setText(hex_text(target.get("txid", "0x7E0"), width=3))
        self.rxid_edit.setText(hex_text(target.get("rxid", "0x7E8"), width=3))
        if "extended_id" in target:
            self.extended_check.setChecked(bool(target.get("extended_id")))
        self.txid_edit.blockSignals(False)
        self.rxid_edit.blockSignals(False)
        self.extended_check.blockSignals(False)
        self.update_effective_preview()

    def populate_cases(self) -> None:
        rows: List[Dict[str, Any]] = []
        for path in self.config_files:
            try:
                data = load_yaml(path)
            except Exception:
                continue
            if isinstance(data.get("testcases"), list):
                for tc in data["testcases"]:
                    if isinstance(tc, dict):
                        rows.append(normalize_testcase_metadata(tc, source_yaml=display_path(path)))
        if not rows:
            for tc in self.config.get("testcases", []):
                if isinstance(tc, dict):
                    rows.append(normalize_testcase_metadata(tc, source_yaml=str(tc.get("source_yaml", "merged config"))))
        self.all_cases = sort_testcases_by_report_order(rows)
        self.apply_filters()

    def apply_filters(self) -> None:
        self.save_current_overrides()
        previous_name = self.current_testcase().get("name") if self.current_testcase() else ""
        category = self.category_filter.currentText()
        group = self.group_filter.currentText()
        filtered: List[Dict[str, Any]] = []
        for tc in self.all_cases:
            if category != "All" and str(tc.get("category", "")) != category:
                continue
            if group != "All" and not str(tc.get("group", "")).startswith(group):
                continue
            filtered.append(tc)
        self.filtered_cases = filtered
        self._updating_ui = True
        self.testcase_combo.blockSignals(True)
        self.testcase_combo.clear()
        for tc in self.filtered_cases:
            self.testcase_combo.addItem(str(tc.get("display_name", tc.get("name", ""))), tc)
        self.testcase_combo.blockSignals(False)
        if previous_name:
            for idx, tc in enumerate(self.filtered_cases):
                if tc.get("name") == previous_name:
                    self.testcase_combo.setCurrentIndex(idx)
                    break
        if self.testcase_combo.currentIndex() < 0 and self.filtered_cases:
            self.testcase_combo.setCurrentIndex(0)
        self._updating_ui = False
        self.current_case_key = self.case_key(self.current_testcase())
        self.rebuild_parameter_form()
        self.update_detail_card()
        self.update_effective_preview()

    def current_testcase(self) -> Dict[str, Any]:
        idx = self.testcase_combo.currentIndex()
        if idx < 0:
            return {}
        data = self.testcase_combo.itemData(idx)
        return copy.deepcopy(data) if isinstance(data, dict) else {}

    def update_detail_card(self) -> None:
        tc = self.current_testcase()
        if not tc:
            self.summary_id_label.setText("Test ID: -")
            self.summary_title_label.setText("Title: No testcase available")
            self.summary_type_label.setText("Type / mode: -")
            self.summary_service_label.setText("Service: -")
            self.summary_safety_label.setText("Flow: -")
            self.summary_objective_label.setText("Objective: -")
            return
        ids = tc.get("test_ids") or []
        objective = str(tc.get("objective", "") or "")
        if len(objective) > 150:
            objective = objective[:147].rstrip() + "..."
        warning = " | metadata warning" if tc.get("metadata_warning") else ""
        destructive = ""
        self.summary_id_label.setText(f"Test ID: {', '.join(ids) if ids else 'UNMAPPED'}")
        self.summary_title_label.setText(f"Title: {tc.get('title', '')}")
        self.summary_type_label.setText(f"Type / mode: {tc.get('type', '')} / {tc.get('mode', '')}")
        self.summary_service_label.setText(f"Service: {tc.get('service', '')} {tc.get('subfunction', '')}".strip())
        self.summary_safety_label.setText(f"Flow: TX/RX observe{warning}")
        self.summary_objective_label.setText(f"Objective: {objective}")

    def selected_testcases(self, selected_only: bool) -> List[Dict[str, Any]]:
        if selected_only:
            tc = self.current_testcase()
            return [tc] if tc else []
        return [copy.deepcopy(tc) for tc in self.filtered_cases]

    def build_runtime_config(self, testcases: List[Dict[str, Any]]) -> Path:
        self.save_current_overrides()
        if not testcases:
            raise ValueError("no testcase selected")
        first_effective = self.effective_config_for_testcase(testcases[0], include_current=self.case_key(testcases[0]) == self.current_case_key)
        cfg = copy.deepcopy(first_effective)
        effective_testcases: List[Dict[str, Any]] = []
        for tc in testcases:
            effective = self.effective_config_for_testcase(tc, include_current=self.case_key(tc) == self.current_case_key)
            effective_testcases.extend(copy.deepcopy(effective.get("testcases", [])))
        cfg["testcases"] = effective_testcases
        cfg.pop("_gui_effective", None)

        tmp_dir = ROOT / ".gui_runtime"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        out = tmp_dir / f"runtime_{time.strftime('%Y%m%d_%H%M%S')}.yaml"
        with out.open("w", encoding="utf-8") as fh:
            yaml.safe_dump(cfg, fh, sort_keys=False, allow_unicode=True)
        return out

    def start_run(self, selected_only: bool) -> None:
        if self.process is not None:
            QMessageBox.warning(self, "Already running", "A testcase run is already in progress.")
            return
        testcases = self.selected_testcases(selected_only)
        if not testcases:
            QMessageBox.warning(self, "No testcase selected", "Select at least one testcase or use Run all.")
            return
        if not self.dry_run_check.isChecked() and not self.can_interface_is_up(show=True):
            QMessageBox.warning(
                self,
                "CAN not ready",
                "SocketCAN is not ready. Click Configure CAN, or run: bash can_config.sh can0",
            )
            return
        validation: List[ValidationMessage] = []
        for tc in testcases:
            try:
                effective = self.effective_config_for_testcase(tc, include_current=self.case_key(tc) == self.current_case_key)
                validation.extend(validate_effective_config(effective))
            except Exception as exc:
                validation.append(ValidationMessage("error", "config", f"{tc.get('name', '<unknown>')}: {exc}"))
        blocking = [msg for msg in validation if msg.severity == "error"]
        if blocking:
            QMessageBox.warning(self, "Validation blocked", "\n".join(f"{m.field}: {m.message}" for m in blocking[:8]))
            self.current_validation = validation
            self.update_validation_view()
            return
        try:
            runtime_config = self.build_runtime_config(testcases)
        except Exception as exc:
            QMessageBox.critical(self, "Runtime config error", str(exc))
            return

        if selected_only and testcases:
            effective = self.effective_config_for_testcase(testcases[0], include_current=True)
            self.append_evidence_header((effective.get("testcases") or [testcases[0]])[0], effective)
        else:
            self.append_log(f"\n===== RUN ALL VISIBLE ({len(testcases)} testcases, sorted by report order) =====")

        args = [str(ROOT / "run_udstk.py"), "-c", str(runtime_config), "--runs-dir", str(ROOT / "runs")]
        if self.dry_run_check.isChecked():
            args.append("--dry-run")
        args.append("--yes-i-am-authorized")
        if self.show_process_check.isChecked():
            args.append("--show-process")
        if self.show_can_check.isChecked():
            args.append("--show-can")
        if self.verbose_check.isChecked():
            args.append("--verbose")

        self.append_log("\n$ " + " ".join([sys.executable] + args))
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(ROOT))
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONUNBUFFERED", "1")
        env.insert("PYTHONPATH", str(ROOT) + os.pathsep + env.value("PYTHONPATH", ""))
        self.process.setProcessEnvironment(env)
        self.process.readyReadStandardOutput.connect(self.read_stdout)
        self.process.readyReadStandardError.connect(self.read_stderr)
        self.process.finished.connect(self.process_finished)
        self.set_running(True)
        self.process.start(sys.executable, args)
        if not self.process.waitForStarted(3000):
            self.append_log("Failed to start runner process.")
            self.process = None
            self.set_running(False)

    def append_evidence_header(self, tc: Mapping[str, Any], effective_config: Mapping[str, Any] | None = None) -> None:
        effective_config = effective_config or {}
        target_name = str(tc.get("target", effective_config.get("default_target", self.config.get("default_target", "ecu1"))))
        target = (effective_config.get("targets") or self.config.get("targets", {})).get(target_name, {})
        params = tc.get("_effective_parameters", {})
        dry_run = bool((effective_config.get("safety") or {}).get("dry_run", self.dry_run_check.isChecked()))
        header = (
            "\n"
            f"===== {tc.get('display_name', tc.get('name'))} =====\n"
            f"Internal name: {tc.get('internal_name', tc.get('name', ''))}\n"
            f"Type: {tc.get('type', '')}\n"
            f"Target: {target_name}\n"
            f"TX/RX: {hex_text(target.get('txid', self.txid_edit.text()), 3)} -> {hex_text(target.get('rxid', self.rxid_edit.text()), 3)}\n"
            f"Session flow: {session_text(tc.get('session_flow', target.get('session_flow', [])))}"
        )
        self.append_log(header)
        self.append_evidence_note(header)

    def set_running(self, running: bool) -> None:
        self.run_selected_btn.setEnabled((not running) and not any(msg.severity == "error" for msg in self.current_validation))
        self.run_all_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.reload_btn.setEnabled(not running)

    def read_stdout(self) -> None:
        if not self.process:
            return
        text = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        self.append_log(text, raw=True)
        self.route_evidence_text(text)
        self.extract_log_dir(text)

    def read_stderr(self) -> None:
        if not self.process:
            return
        text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        self.append_log(text, raw=True)
        self.route_evidence_text(text)
        self.extract_log_dir(text)

    def route_evidence_text(self, text: str) -> None:
        for line in text.splitlines():
            upper = line.upper()
            if "CAN TX" in upper or "CAN RX" in upper or " TX  " in line or " RX  " in line:
                self.append_to_view(self.can_view, line + "\n", raw=True)
            if "VERDICT" in upper or "PASS_" in upper or "FAIL_" in upper or "NRC_" in upper:
                self.append_to_view(self.verdict_view, line + "\n", raw=True)
            if "TESTCASE" in upper or "=====" in line or "DRY-RUN" in upper or "SAFETY" in upper or "REFUSING" in upper:
                self.append_evidence_note(line)

    def extract_log_dir(self, text: str) -> None:
        for match in re.finditer(r"logs:\s*(.+)", text):
            path = Path(match.group(1).strip())
            if not path.is_absolute():
                path = ROOT / path
            self.last_log_dir = path
            self.open_logs_btn.setEnabled(True)

    def process_finished(self, exit_code: int, exit_status: QProcess.ExitStatus) -> None:
        status = "normal" if exit_status == QProcess.ExitStatus.NormalExit else "crashed"
        self.append_log(f"\n[process finished] exit_code={exit_code} status={status}")
        self.process = None
        self.set_running(False)

    def stop_process(self) -> None:
        if self.process:
            self.append_log("\n[stop requested]")
            self.process.kill()

    def open_last_log_dir(self) -> None:
        if self.last_log_dir and self.last_log_dir.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.last_log_dir)))
        else:
            QMessageBox.information(self, "No log folder", "No completed log folder is available yet.")

    def clear_evidence_views(self) -> None:
        self.live_log_view.clear()
        self.can_view.clear()
        self.verdict_view.clear()
        self.evidence_view.clear()
        self.command_preview_view.clear()

    def append_log(self, text: str, raw: bool = False) -> None:
        self.append_to_view(self.live_log_view, text, raw=raw)

    def append_evidence_note(self, text: str) -> None:
        self.append_to_view(self.evidence_view, text + "\n", raw=True)

    def append_to_view(self, view: QTextEdit, text: str, raw: bool = False) -> None:
        view.moveCursor(QTextCursor.MoveOperation.End)
        chunks = text.splitlines(True) or [text]
        for chunk in chunks:
            fmt = QTextCharFormat()
            fmt.setForeground(QColor(self.log_color_for_line(chunk)))
            view.setCurrentCharFormat(fmt)
            view.insertPlainText(chunk if raw or chunk.endswith("\n") else chunk + "\n")
        view.moveCursor(QTextCursor.MoveOperation.End)

    def log_color_for_line(self, line: str) -> str:
        upper = line.upper()
        if "ERROR" in upper or "EXCEPTION" in upper or "FAIL" in upper or "TRACEBACK" in upper:
            return "#ff7b7b"
        if "NRC_" in upper or " 7F " in upper or "NEGATIVE" in upper:
            return "#fbbf24"
        if "POSITIVE" in upper or "PASS" in upper:
            return "#81e6a5"
        if " RX " in line or " CAN RX " in upper:
            return "#6ee7b7"
        if " TX " in line or " CAN TX " in upper:
            return "#7dd3fc"
        if line.startswith("=====") or "=====" in line:
            return "#c084fc"
        if line.lstrip().startswith("$ "):
            return "#93c5fd"
        if "logs:" in line:
            return "#a7f3d0"
        return "#d7dde7"


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = UdsObserverGui()
    win.showMaximized()
    win.sync_window_action_labels()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
