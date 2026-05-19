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
    from PySide6.QtCore import QProcess, QProcessEnvironment, Qt, QUrl
    from PySide6.QtGui import QDesktopServices, QFont, QTextCursor
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QComboBox,
        QFileDialog,
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
        self.process: Optional[QProcess] = None
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
        self.fullscreen_btn = QPushButton("Full screen")
        self.fullscreen_btn.setToolTip("Toggle full screen (F11). Press Esc to leave full screen.")
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

        cfg_group = QGroupBox("Config files")
        cfg_layout = QVBoxLayout(cfg_group)
        self.config_list = QListWidget()
        self.config_list.setMinimumHeight(64)
        self.config_list.setMaximumHeight(112)
        cfg_layout.addWidget(self.config_list)
        cfg_btns = QHBoxLayout()
        self.add_cfg_btn = QPushButton("Add YAML")
        self.remove_cfg_btn = QPushButton("Remove")
        self.reload_btn = QPushButton("Reload")
        cfg_btns.addWidget(self.add_cfg_btn)
        cfg_btns.addWidget(self.remove_cfg_btn)
        cfg_btns.addWidget(self.reload_btn)
        cfg_layout.addLayout(cfg_btns)
        left_body_layout.addWidget(cfg_group)

        target_group = QGroupBox("Connection / target override")
        target_layout = QVBoxLayout(target_group)
        self.channel_edit = QLineEdit("can0")
        self.interface_edit = QLineEdit("socketcan")
        self.target_combo = QComboBox()
        self.txid_edit = QLineEdit("0x681")
        self.rxid_edit = QLineEdit("0x601")
        self.session_edit = QLineEdit("03")
        self.extended_check = QCheckBox("29-bit extended CAN ID")
        for label, widget in (
            ("Channel", self.channel_edit),
            ("Interface", self.interface_edit),
            ("Target", self.target_combo),
            ("TX ID", self.txid_edit),
            ("RX ID", self.rxid_edit),
            ("Session flow", self.session_edit),
        ):
            row = QHBoxLayout()
            row.addWidget(QLabel(label), 0)
            row.addWidget(widget, 1)
            target_layout.addLayout(row)
        target_layout.addWidget(self.extended_check)
        left_body_layout.addWidget(target_group)

        options_group = QGroupBox("Run options")
        options_layout = QVBoxLayout(options_group)
        self.dry_run_check = QCheckBox("Dry run / validate only")
        self.authorized_check = QCheckBox("I am authorized to run fuzzing/probing")
        self.show_process_check = QCheckBox("Show process steps")
        self.show_process_check.setChecked(True)
        self.show_can_check = QCheckBox("Show CAN TX")
        self.verbose_check = QCheckBox("Verbose RX/debug")
        for cb in (self.dry_run_check, self.authorized_check, self.show_process_check, self.show_can_check, self.verbose_check):
            options_layout.addWidget(cb)
        left_body_layout.addWidget(options_group)

        selector_group = QGroupBox("Testcase selector")
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
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)
        self.detail_view.setMinimumHeight(140)
        selector_layout.addWidget(self.detail_view)
        left_body_layout.addWidget(selector_group)
        left_body_layout.addStretch(1)

        run_row = QHBoxLayout()
        self.run_selected_btn = QPushButton("Run selected")
        self.run_selected_btn.setObjectName("runButton")
        self.run_all_btn = QPushButton("Run all")
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
        self.tabs.addTab(self.live_log_view, "Live Output")
        self.tabs.addTab(self.can_view, "CAN Frames / TX-RX")
        self.tabs.addTab(self.verdict_view, "Verdict Summary")
        self.tabs.addTab(self.evidence_view, "Evidence Notes / Step Details")

        log_buttons = QHBoxLayout()
        self.clear_log_btn = QPushButton("Clear evidence views")
        log_buttons.addWidget(self.clear_log_btn)
        log_buttons.addStretch(1)
        right_layout.addLayout(log_buttons)

        splitter.setChildrenCollapsible(False)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([430, 930])

        self.fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        self.add_cfg_btn.clicked.connect(self.add_config_file)
        self.remove_cfg_btn.clicked.connect(self.remove_config_file)
        self.reload_btn.clicked.connect(self.reload_config_and_cases)
        self.target_combo.currentTextChanged.connect(self.populate_target_fields)
        self.category_filter.currentTextChanged.connect(self.apply_filters)
        self.group_filter.currentTextChanged.connect(self.apply_filters)
        self.testcase_combo.currentIndexChanged.connect(self.update_detail_card)
        self.run_selected_btn.clicked.connect(lambda: self.start_run(selected_only=True))
        self.run_all_btn.clicked.connect(lambda: self.start_run(selected_only=False))
        self.stop_btn.clicked.connect(self.stop_process)
        self.open_logs_btn.clicked.connect(self.open_last_log_dir)
        self.clear_log_btn.clicked.connect(self.clear_evidence_views)

    def _make_log_view(self) -> QTextEdit:
        view = QTextEdit()
        view.setReadOnly(True)
        view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        return view

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
        else:
            self.showFullScreen()
            self.fullscreen_btn.setText("Exit full screen")

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
        self.channel_edit.setText(str(can_cfg.get("channel", "can0")))
        self.interface_edit.setText(str(can_cfg.get("interface", "socketcan")))
        self.extended_check.setChecked(bool(can_cfg.get("extended_id", False)))
        self.populate_target_fields(self.target_combo.currentText())

    def populate_target_fields(self, target_name: str) -> None:
        targets = self.config.get("targets") or {}
        target = targets.get(target_name) or {}
        self.txid_edit.setText(hex_text(target.get("txid", "0x7E0"), width=3))
        self.rxid_edit.setText(hex_text(target.get("rxid", "0x7E8"), width=3))
        self.session_edit.setText(session_text(target.get("session_flow", [])))
        if "extended_id" in target:
            self.extended_check.setChecked(bool(target.get("extended_id")))

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
        self.update_detail_card()

    def current_testcase(self) -> Dict[str, Any]:
        idx = self.testcase_combo.currentIndex()
        if idx < 0:
            return {}
        data = self.testcase_combo.itemData(idx)
        return copy.deepcopy(data) if isinstance(data, dict) else {}

    def update_detail_card(self) -> None:
        tc = self.current_testcase()
        if not tc:
            self.detail_view.setPlainText("No testcase available for the current filters.")
            return
        ids = tc.get("test_ids") or []
        lines = [
            f"Test ID(s): {', '.join(ids) if ids else 'UNMAPPED'}",
            f"Title: {tc.get('title', '')}",
            f"Internal name: {tc.get('internal_name', tc.get('name', ''))}",
            f"Source YAML: {tc.get('source_yaml', '')}",
            f"Service: {tc.get('service', '')}",
            f"Subfunction: {tc.get('subfunction', '')}",
            f"Mode: {tc.get('mode', '')}",
            f"Target: {tc.get('target', self.config.get('default_target', ''))}",
            f"Group: {tc.get('group', '')}",
            f"Category: {tc.get('category', '')}",
            f"Safety: {tc.get('safety_level', '')}",
            f"Destructive confirm required: {bool(tc.get('destructive_confirm_required', False))}",
            "",
            "Objective:",
            str(tc.get("objective", "")),
            "",
            "Expected behavior:",
            str(tc.get("expected_behavior", "")),
            "",
            "Threat condition:",
            str(tc.get("threat_condition", "")),
        ]
        if tc.get("metadata_warning"):
            lines.extend(["", "Warning:", str(tc["metadata_warning"])])
        if tc.get("safety_level") == "disruptive" and not bool(tc.get("destructive_confirm", False)):
            lines.extend(["", "Safety guard:", "Real transmission is blocked until destructive_confirm: true is set in YAML."])
        self.detail_view.setPlainText("\n".join(lines))

    def selected_testcases(self, selected_only: bool) -> List[Dict[str, Any]]:
        if selected_only:
            tc = self.current_testcase()
            return [tc] if tc else []
        return [copy.deepcopy(tc) for tc in self.all_cases]

    def build_runtime_config(self, testcases: List[Dict[str, Any]]) -> Path:
        cfg = copy.deepcopy(self.config)
        cfg["testcases"] = testcases
        cfg.setdefault("can", {})
        cfg["can"]["channel"] = self.channel_edit.text().strip() or "can0"
        cfg["can"]["interface"] = self.interface_edit.text().strip() or "socketcan"
        cfg["can"]["extended_id"] = bool(self.extended_check.isChecked())
        cfg.setdefault("safety", {})
        cfg["safety"]["authorized"] = bool(self.authorized_check.isChecked())

        target_name = self.target_combo.currentText().strip() or str(cfg.get("default_target", "ecu1"))
        cfg["default_target"] = target_name
        cfg.setdefault("targets", {})
        cfg["targets"].setdefault(target_name, {})
        cfg["targets"][target_name]["txid"] = parse_hex_int(self.txid_edit.text())
        cfg["targets"][target_name]["rxid"] = parse_hex_int(self.rxid_edit.text())
        cfg["targets"][target_name]["session_flow"] = parse_byte_list(self.session_edit.text())
        cfg["targets"][target_name]["extended_id"] = bool(self.extended_check.isChecked())

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
        if not self.dry_run_check.isChecked():
            disruptive = [tc for tc in testcases if tc.get("safety_level") == "disruptive" and not bool(tc.get("destructive_confirm", False))]
            if disruptive:
                QMessageBox.warning(
                    self,
                    "Destructive confirmation required",
                    "Selected testcase is marked disruptive and destructive_confirm is false. Real transmission is refused.",
                )
                return
        has_authorized_probe = any(
            str(tc.get("type", "")).endswith("fuzzer") or str(tc.get("type", "")) == "uds_access_control_probe"
            for tc in testcases
        )
        if has_authorized_probe and not self.authorized_check.isChecked() and not self.dry_run_check.isChecked():
            QMessageBox.warning(
                self,
                "Authorization required",
                "Selected cases include fuzzing/probing. Tick the authorization checkbox or use Dry run.",
            )
            return
        try:
            runtime_config = self.build_runtime_config(testcases)
        except Exception as exc:
            QMessageBox.critical(self, "Runtime config error", str(exc))
            return

        if selected_only and testcases:
            self.append_evidence_header(testcases[0])
        else:
            self.append_log(f"\n===== RUN ALL ({len(testcases)} testcases, sorted by report order) =====")

        args = [str(ROOT / "run_udstk.py"), "-c", str(runtime_config), "--runs-dir", str(ROOT / "runs")]
        if self.dry_run_check.isChecked():
            args.append("--dry-run")
        if self.authorized_check.isChecked():
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

    def append_evidence_header(self, tc: Mapping[str, Any]) -> None:
        target = self.config.get("targets", {}).get(str(tc.get("target", self.config.get("default_target", "ecu1"))), {})
        header = (
            "\n"
            f"===== {tc.get('display_name', tc.get('name'))} =====\n"
            f"Internal name: {tc.get('internal_name', tc.get('name', ''))}\n"
            f"Target: {tc.get('target', self.config.get('default_target', 'ecu1'))}\n"
            f"TX/RX: {hex_text(target.get('txid', self.txid_edit.text()), 3)} -> {hex_text(target.get('rxid', self.rxid_edit.text()), 3)}\n"
            f"Session flow: {session_text(tc.get('session_flow', target.get('session_flow', [])))}\n"
            f"Mode: {tc.get('mode', tc.get('type', ''))}"
        )
        self.append_log(header)
        self.append_evidence_note(header)

    def set_running(self, running: bool) -> None:
        self.run_selected_btn.setEnabled(not running)
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

    def append_log(self, text: str, raw: bool = False) -> None:
        self.append_to_view(self.live_log_view, text, raw=raw)

    def append_evidence_note(self, text: str) -> None:
        self.append_to_view(self.evidence_view, text + "\n", raw=True)

    def append_to_view(self, view: QTextEdit, text: str, raw: bool = False) -> None:
        if raw:
            view.moveCursor(QTextCursor.MoveOperation.End)
            view.insertPlainText(text)
        else:
            view.append(text)
        view.moveCursor(QTextCursor.MoveOperation.End)


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = UdsObserverGui()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
