#!/usr/bin/env python3
import sys
import os
import json
import glob
from pathlib import Path
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QLabel, QLineEdit, QSpinBox, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QTextEdit
)
from PySide6.QtCore import QProcess, QTimer, Qt
from PySide6.QtGui import QFont, QColor

class PoppyGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Poppy V5 — Dynamic Instrumentation Command Center")
        self.resize(1200, 800)

        # State management
        self.observer_process = None
        self.injector_process = None
        self.active_log_file = None
        self.log_file_handle = None
        
        # Log tailing timer
        self.tail_timer = QTimer()
        self.tail_timer.timeout.connect(self.read_new_log_lines)

        self.setup_ui()

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout(main_widget)

        # Left Panel: Controls
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setAlignment(Qt.AlignTop)

        # -- Observer Configuration --
        obs_group = QGroupBox("1. Observe (Frida + DTrace)")
        obs_layout = QVBoxLayout()
        
        obs_layout.addWidget(QLabel("Target Daemon (e.g., tipsd, fskitd):"))
        self.daemon_input = QLineEdit("tipsd")
        obs_layout.addWidget(self.daemon_input)
        
        obs_layout.addWidget(QLabel("Duration (seconds):"))
        self.duration_spin = QSpinBox()
        self.duration_spin.setRange(10, 3600)
        self.duration_spin.setValue(60)
        obs_layout.addWidget(self.duration_spin)

        self.btn_start_obs = QPushButton("Start Observer")
        self.btn_start_obs.clicked.connect(self.start_observer)
        self.btn_start_obs.setStyleSheet("background-color: #2E8B57; color: white; font-weight: bold; padding: 8px;")
        obs_layout.addWidget(self.btn_start_obs)
        
        self.btn_stop_obs = QPushButton("Stop Observer")
        self.btn_stop_obs.clicked.connect(self.stop_observer)
        self.btn_stop_obs.setEnabled(False)
        obs_layout.addWidget(self.btn_stop_obs)
        
        obs_group.setLayout(obs_layout)
        left_layout.addWidget(obs_group)

        # -- Injector Configuration --
        inj_group = QGroupBox("2. Fault Injection")
        inj_layout = QVBoxLayout()
        
        inj_layout.addWidget(QLabel("Variants:"))
        self.variant_combo = QComboBox()
        self.variant_combo.addItems(["all", "empty", "size", "nest", "type"])
        inj_layout.addWidget(self.variant_combo)

        self.btn_fire_inject = QPushButton("Fire Injection")
        self.btn_fire_inject.clicked.connect(self.fire_injection)
        self.btn_fire_inject.setStyleSheet("background-color: #A52A2A; color: white; font-weight: bold; padding: 8px;")
        inj_layout.addWidget(self.btn_fire_inject)
        
        inj_group.setLayout(inj_layout)
        left_layout.addWidget(inj_group)

        # -- System Console --
        console_group = QGroupBox("System Output")
        console_layout = QVBoxLayout()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Menlo", 11))
        self.console.setStyleSheet("background-color: #1E1E1E; color: #D4D4D4;")
        console_layout.addWidget(self.console)
        console_group.setLayout(console_layout)
        left_layout.addWidget(console_group)

        # Right Panel: Live Dashboard
        right_panel = QGroupBox("Live JSONL Dashboard")
        right_layout = QVBoxLayout(right_panel)
        
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Time", "PID", "Kind", "Data"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setFont(QFont("Menlo", 12))
        right_layout.addWidget(self.table)

        # Assemble Splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 900])
        
        layout.addWidget(splitter)

    def log_sys(self, msg):
        """Helper to print to the internal system console."""
        self.console.append(msg)
        self.console.ensureCursorVisible()

    def start_observer(self):
        daemon = self.daemon_input.text().strip()
        duration = self.duration_spin.value()
        if not daemon:
            self.log_sys("[!] No daemon specified.")
            return

        self.table.setRowCount(0)
        self.log_sys(f"[*] Starting observer for {daemon} ({duration}s)...")
        
        # Setup QProcess
        self.observer_process = QProcess()
        self.observer_process.setProcessChannelMode(QProcess.MergedChannels)
        self.observer_process.readyReadStandardOutput.connect(self.handle_obs_stdout)
        self.observer_process.finished.connect(self.observer_finished)

        # Execute poppy.py run
        cmd = "python3"
        args = ["poppy.py", "run", "--daemon", daemon, "--duration", str(duration)]
        self.observer_process.start(cmd, args)

        self.btn_start_obs.setEnabled(False)
        self.btn_stop_obs.setEnabled(True)
        
        # Start a slight delay timer to find the newly created jsonl file
        QTimer.singleShot(1500, lambda: self.hook_latest_jsonl(daemon))

    def hook_latest_jsonl(self, daemon):
        """Finds the newest jsonl file for the daemon and starts tailing it."""
        runs_dir = Path("runs")
        if not runs_dir.exists():
            return
            
        files = glob.glob(f"runs/poppy_{daemon}_*.jsonl")
        # Filter out dtrace files so we target the main frida log first
        main_files = [f for f in files if "dtrace" not in f]
        
        if main_files:
            latest_file = max(main_files, key=os.path.getctime)
            self.active_log_file = latest_file
            self.log_sys(f"[*] Tailing live log: {latest_file}")
            
            self.log_file_handle = open(self.active_log_file, 'r', encoding='utf-8')
            # Seek to end so we only get fresh events if appending, 
            # but since it's a new file, starting at 0 is fine.
            self.tail_timer.start(500) # Poll every 500ms
        else:
            self.log_sys("[!] Could not locate a new JSONL file to tail.")

    def read_new_log_lines(self):
        """Reads new lines from the active JSONL file and populates the table."""
        if not self.log_file_handle:
            return

        lines = self.log_file_handle.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                self.add_table_row(ev)
            except json.JSONDecodeError:
                pass

    def add_table_row(self, ev):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        # Extract schema fields
        ts = str(ev.get('ts', ''))
        pid = str(ev.get('pid', ''))
        kind = ev.get('kind', 'unknown')
        
        # Clean up data payload for display
        data_payload = ev.get('data', {})
        if not isinstance(data_payload, dict):
            data_str = str(data_payload)
        else:
            data_str = json.dumps(data_payload)

        # Highlight important events
        kind_item = QTableWidgetItem(kind)
        if "error" in kind.lower() or "reject" in kind.lower() or "fatal" in kind.lower():
            kind_item.setForeground(QColor("#FF4500"))
        elif "accept" in kind.lower() or "granted" in kind.lower():
            kind_item.setForeground(QColor("#32CD32"))

        self.table.setItem(row, 0, QTableWidgetItem(ts))
        self.table.setItem(row, 1, QTableWidgetItem(pid))
        self.table.setItem(row, 2, kind_item)
        self.table.setItem(row, 3, QTableWidgetItem(data_str))
        
        self.table.scrollToBottom()

    def handle_obs_stdout(self):
        data = self.observer_process.readAllStandardOutput().data().decode('utf8')
        self.console.append(data.strip())

    def stop_observer(self):
        if self.observer_process and self.observer_process.state() == QProcess.Running:
            self.log_sys("[*] Sending termination signal to observer...")
            self.observer_process.terminate()
            
        self.tail_timer.stop()
        if self.log_file_handle:
            self.log_file_handle.close()
            self.log_file_handle = None

    def observer_finished(self):
        self.log_sys("[*] Observer process finished.")
        self.btn_start_obs.setEnabled(True)
        self.btn_stop_obs.setEnabled(False)
        self.tail_timer.stop()

    def fire_injection(self):
        daemon = self.daemon_input.text().strip()
        variant = self.variant_combo.currentText()
        if not daemon:
            self.log_sys("[!] No daemon specified for injection.")
            return

        self.log_sys(f"[>>>] Firing fault injection: {daemon} -> {variant}...")
        
        self.injector_process = QProcess()
        self.injector_process.setProcessChannelMode(QProcess.MergedChannels)
        self.injector_process.readyReadStandardOutput.connect(
            lambda: self.console.append(self.injector_process.readAllStandardOutput().data().decode('utf8').strip())
        )
        
        cmd = "python3"
        args = ["poppy.py", "inject", "--daemon", daemon, "--variants", variant]
        self.injector_process.start(cmd, args)

    def closeEvent(self, event):
        """Cleanup processes on exit."""
        self.stop_observer()
        if self.injector_process and self.injector_process.state() == QProcess.Running:
            self.injector_process.terminate()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion") # Clean cross-platform style
    window = PoppyGUI()
    window.show()
    sys.exit(app.exec())
