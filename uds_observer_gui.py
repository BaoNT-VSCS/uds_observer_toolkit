#!/usr/bin/env python3
"""
UDS Observer Toolkit GUI

Single GUI entry point for the config-driven UDS observer toolkit.
Run:
    python3 uds_observer_gui.py

The GUI keeps the toolkit extensible: new test cases are still added as YAML
under testcases/, then loaded/reloaded from this window. Execution is delegated
to run_udstk.py so the GUI and CLI share the same runner, logger, ISO-TP, UDS
client, and testcase plugins.
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
        QHeaderView,
        QLabel,
        QLineEdit,
        QListWidget,
        QMainWindow,
        QMessageBox,
        QPushButton,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QVBoxLayout,
        QWidget,
    )
except ImportError as exc:  # pragma: no cover - startup guard
    print("Missing dependency: PySide6. Install with: pip install -r requirements.txt", file=sys.stderr)
    raise SystemExit(2) from exc

APP_TITLE = "UDS Observer Toolkit"

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG_FILES = [
    ROOT / "configs" / "default.yaml",
    ROOT / "testcases" / "security_access.yaml",
    ROOT / "testcases" / "seed_sampling.yaml",
    ROOT / "testcases" / "fuzzing_basic.yaml",
]

STYLE = """
QWidget {
    background: #12161c;
    color: #d7dde7;
    font-family: Consolas, "JetBrains Mono", monospace;
    font-size: 12px;
}
QGroupBox {
    border: 1px solid #2a3340;
    border-radius: 6px;
    margin-top: 8px;
    padding: 8px;
    background: #171c24;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
    color: #7db3ff;
    font-weight: bold;
}
QLineEdit, QComboBox, QListWidget, QTableWidget, QTextEdit {
    background: #0b0f14;
    border: 1px solid #2a3340;
    border-radius: 4px;
    color: #d7dde7;
    selection-background-color: #1f4f86;
}
QLineEdit, QComboBox {
    padding: 4px 6px;
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
QHeaderView::section {
    background: #1c2430;
    color: #9ba7b8;
    border: 0;
    border-right: 1px solid #2a3340;
    padding: 5px;
}
QCheckBox { spacing: 6px; }
QSplitter::handle { background: #2a3340; }
"""


def load_yaml(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"YAML root must be a mapping: {path}")
    return data


def deep_merge(base: Dict[str, Any], override: Mapping[str, Any]) -> Dict[str, Any]:
    """Merge YAML configs; concatenate testcase lists instead of overwriting them."""
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
        return str(path.relative_to(ROOT))
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
        self.resize(1320, 820)
        self.config_files: List[Path] = [p for p in DEFAULT_CONFIG_FILES if p.exists()]
        self.config: Dict[str, Any] = {}
        self.process: Optional[QProcess] = None
        self.last_log_dir: Optional[Path] = None
        self._build_ui()
        self.reload_config_and_cases()

    def _build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)

        header = QHBoxLayout()
        title = QLabel("UDS Observer Toolkit")
        title.setFont(QFont("Consolas", 16, QFont.Weight.Bold))
        subtitle = QLabel("single GUI entrypoint / config-driven testcase runner")
        subtitle.setStyleSheet("color:#8b96a8")
        header.addWidget(title)
        header.addWidget(subtitle)
        header.addStretch(1)
        main.addLayout(header)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        splitter.addWidget(left)

        cfg_group = QGroupBox("Config files")
        cfg_layout = QVBoxLayout(cfg_group)
        self.config_list = QListWidget()
        cfg_layout.addWidget(self.config_list)
        cfg_btns = QHBoxLayout()
        self.add_cfg_btn = QPushButton("Add YAML")
        self.remove_cfg_btn = QPushButton("Remove")
        self.reload_btn = QPushButton("Reload")
        cfg_btns.addWidget(self.add_cfg_btn)
        cfg_btns.addWidget(self.remove_cfg_btn)
        cfg_btns.addWidget(self.reload_btn)
        cfg_layout.addLayout(cfg_btns)
        left_layout.addWidget(cfg_group, 2)

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
        left_layout.addWidget(target_group, 2)

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
        left_layout.addWidget(options_group, 1)

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
        left_layout.addStretch(1)

        center = QWidget()
        center_layout = QVBoxLayout(center)
        splitter.addWidget(center)

        case_group = QGroupBox("Test cases")
        case_layout = QVBoxLayout(case_group)
        case_btns = QHBoxLayout()
        self.select_all_btn = QPushButton("Select all")
        self.select_none_btn = QPushButton("Select none")
        case_btns.addWidget(self.select_all_btn)
        case_btns.addWidget(self.select_none_btn)
        case_btns.addStretch(1)
        case_layout.addLayout(case_btns)
        self.case_table = QTableWidget(0, 5)
        self.case_table.setHorizontalHeaderLabels(["Run", "Name", "Type", "Target", "Source"])
        self.case_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.case_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.case_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.case_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.case_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.case_table.setAlternatingRowColors(True)
        case_layout.addWidget(self.case_table)
        center_layout.addWidget(case_group, 1)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        splitter.addWidget(right)
        log_group = QGroupBox("Live output")
        log_layout = QVBoxLayout(log_group)
        log_buttons = QHBoxLayout()
        self.clear_log_btn = QPushButton("Clear")
        log_buttons.addWidget(self.clear_log_btn)
        log_buttons.addStretch(1)
        log_layout.addLayout(log_buttons)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        log_layout.addWidget(self.log_view)
        right_layout.addWidget(log_group, 1)

        splitter.setSizes([360, 560, 520])

        self.add_cfg_btn.clicked.connect(self.add_config_file)
        self.remove_cfg_btn.clicked.connect(self.remove_config_file)
        self.reload_btn.clicked.connect(self.reload_config_and_cases)
        self.target_combo.currentTextChanged.connect(self.populate_target_fields)
        self.select_all_btn.clicked.connect(lambda: self.set_all_cases_checked(True))
        self.select_none_btn.clicked.connect(lambda: self.set_all_cases_checked(False))
        self.run_selected_btn.clicked.connect(lambda: self.start_run(selected_only=True))
        self.run_all_btn.clicked.connect(lambda: self.start_run(selected_only=False))
        self.stop_btn.clicked.connect(self.stop_process)
        self.open_logs_btn.clicked.connect(self.open_last_log_dir)
        self.clear_log_btn.clicked.connect(self.log_view.clear)

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
        self.append_log(f"Loaded {len(self.config_files)} config file(s), {self.case_table.rowCount()} testcase(s).")

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
        self.case_table.setRowCount(0)
        # Keep the source file visible by re-reading each testcase file directly.
        rows: List[tuple[Dict[str, Any], str]] = []
        base_without_cases: Dict[str, Any] = {}
        for path in self.config_files:
            try:
                data = load_yaml(path)
            except Exception:
                continue
            if isinstance(data.get("testcases"), list):
                for tc in data["testcases"]:
                    if isinstance(tc, dict):
                        rows.append((copy.deepcopy(tc), display_path(path)))
            else:
                base_without_cases = deep_merge(base_without_cases, data)
        if not rows:
            for tc in self.config.get("testcases", []):
                rows.append((copy.deepcopy(tc), "merged config"))

        for tc, source in rows:
            row = self.case_table.rowCount()
            self.case_table.insertRow(row)
            chk = QTableWidgetItem("")
            chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk.setCheckState(Qt.CheckState.Unchecked)
            chk.setData(Qt.ItemDataRole.UserRole, tc)
            self.case_table.setItem(row, 0, chk)
            self.case_table.setItem(row, 1, QTableWidgetItem(str(tc.get("name", ""))))
            self.case_table.setItem(row, 2, QTableWidgetItem(str(tc.get("type", ""))))
            self.case_table.setItem(row, 3, QTableWidgetItem(str(tc.get("target", self.config.get("default_target", "")))))
            self.case_table.setItem(row, 4, QTableWidgetItem(source))

    def set_all_cases_checked(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        for row in range(self.case_table.rowCount()):
            self.case_table.item(row, 0).setCheckState(state)

    def selected_testcases(self, selected_only: bool) -> List[Dict[str, Any]]:
        out = []
        for row in range(self.case_table.rowCount()):
            item = self.case_table.item(row, 0)
            if not selected_only or item.checkState() == Qt.CheckState.Checked:
                tc = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(tc, dict):
                    out.append(copy.deepcopy(tc))
        return out

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
        has_fuzzer = any(str(tc.get("type", "")).endswith("fuzzer") for tc in testcases)
        if has_fuzzer and not self.authorized_check.isChecked() and not self.dry_run_check.isChecked():
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
        self.extract_log_dir(text)

    def read_stderr(self) -> None:
        if not self.process:
            return
        text = bytes(self.process.readAllStandardError()).decode("utf-8", errors="replace")
        self.append_log(text, raw=True)
        self.extract_log_dir(text)

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

    def append_log(self, text: str, raw: bool = False) -> None:
        if raw:
            self.log_view.moveCursor(QTextCursor.MoveOperation.End)
            self.log_view.insertPlainText(text)
        else:
            self.log_view.append(text)
        self.log_view.moveCursor(QTextCursor.MoveOperation.End)


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = UdsObserverGui()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
