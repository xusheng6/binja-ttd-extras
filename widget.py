"""Binary Ninja command UI for extracted TTD API calls."""
import os
import subprocess
import sys

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
                               QFileDialog, QTableView, QTextEdit, QLabel, QMessageBox)

from .extractor import command
from .report import Report


class CallModel(QAbstractTableModel):
    HEADERS = ('#', 'Position', 'TID', 'Module', 'Function', 'Parameters', 'Return', 'Return Address')

    def __init__(self, parent=None):
        super().__init__(parent)
        self.report = None
        self.rows = None

    def set_report(self, report):
        self.beginResetModel()
        self.report = report
        self.rows = None
        self.endResetModel()

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() or not self.report else (len(self.rows) if self.rows is not None else self.report.call_count)

    def columnCount(self, parent=QModelIndex()):
        return len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return None

    def call_at(self, row):
        return self.report.call(self.rows[row] if self.rows is not None else row)

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or role != Qt.DisplayRole:
            return None
        call = self.call_at(index.row())
        values = (str(call.index), call.position, str(call.tid), call.module, call.api,
                  call.search.decode('utf-8', 'replace'), hex(call.ret), hex(call.return_address))
        return values[index.column()]


class BehaviorDialog(QDialog):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.report = None
        self.process = None
        self.setWindowTitle('TTD Behavior')
        self.resize(1250, 750)
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        load = QPushButton('Load Report…')
        load.clicked.connect(self.load_report)
        buttons.addWidget(load)
        if sys.platform == 'win32':
            extract = QPushButton('Extract…')
            extract.clicked.connect(self.extract)
            buttons.addWidget(extract)
        self.status = QLabel('Open a .ttdb report')
        buttons.addWidget(self.status, 1)
        layout.addLayout(buttons)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText('module:kernel32 api:WriteFile ret:!0')
        self.filter.textChanged.connect(self.schedule_filter)
        layout.addWidget(self.filter)
        self.model = CallModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QTableView.SelectRows)
        self.table.doubleClicked.connect(self.travel)
        self.table.selectionModel().currentRowChanged.connect(self.show_detail)
        layout.addWidget(self.table, 3)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        layout.addWidget(self.detail, 1)
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(150)
        self.timer.timeout.connect(self.apply_filter)

    def load_report(self, path=None):
        if not path:
            path, _ = QFileDialog.getOpenFileName(self, 'Open TTD report', '', 'TTD reports (*.ttdb)')
        if not path:
            return
        try:
            report = Report(path)
        except Exception as error:
            QMessageBox.critical(self, 'Invalid TTD report', str(error))
            return
        old = self.report
        self.report = report
        self.model.set_report(report)
        if old:
            old.close()
        self.apply_filter()

    def schedule_filter(self):
        self.timer.start()

    def apply_filter(self):
        if not self.report:
            return
        expression = self.filter.text().strip()
        try:
            rows = list(self.report.query(expression)) if expression else None
        except ValueError as error:
            self.status.setText(str(error))
            return
        self.model.set_rows(rows)
        self.status.setText(f'{self.model.rowCount():,} / {self.report.call_count:,} calls')

    def show_detail(self, current, previous):
        if not current.isValid() or not self.report:
            return
        call = self.model.call_at(current.row())
        try:
            params = self.report.parameters(call)
            lines = [f'{call.module}!{call.api} at {call.position}',
                     f'Thread: {call.tid}  Return: {call.ret:#x}  Call site: {call.return_address:#x}',
                     'Metadata decoded' if call.decoded else 'Heuristic arguments', '']
            for param in params:
                lines.append(str(param) + (' [Out]' if param.out else ''))
                if param.data:
                    lines.append(param.data[:4096].hex(' '))
            self.detail.setPlainText('\n'.join(lines))
        except ValueError as error:
            self.detail.setPlainText(str(error))

    def travel(self, index):
        call = self.model.call_at(index.row())
        try:
            from debugger import DebuggerController
            controller = DebuggerController(self.bv)
            if not controller.set_ttd_position(call.position):
                raise RuntimeError('TTD navigation failed; open the matching trace first')
            ip = controller.ip
            if ip:
                self.bv.navigate(self.bv.view, ip)
        except Exception as error:
            QMessageBox.warning(self, 'TTD navigation', str(error))

    def extract(self):
        trace, _ = QFileDialog.getOpenFileName(self, 'Select TTD trace', '', 'TTD traces (*.run)')
        if not trace:
            return
        output = os.path.splitext(trace)[0] + '.ttdb'
        if os.path.exists(output):
            self.load_report(output)
            return
        try:
            args = command(trace, output)
            self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            self.status.setText('Extracting…')
            self.poll = QTimer(self)
            self.poll.timeout.connect(lambda: self.check_extraction(output))
            self.poll.start(300)
        except Exception as error:
            QMessageBox.critical(self, 'Extraction failed', str(error))

    def check_extraction(self, output):
        if self.process.poll() is None:
            return
        self.poll.stop()
        if self.process.returncode == 0:
            self.load_report(output)
        else:
            QMessageBox.critical(self, 'Extraction failed', self.process.stderr.read().decode('utf-8', 'replace')[-4000:])

    def closeEvent(self, event):
        if self.process and self.process.poll() is None:
            self.process.terminate()
        if self.report:
            self.report.close()
        super().closeEvent(event)


_dialogs = []


def open_behavior(bv):
    dialog = BehaviorDialog(bv)
    _dialogs.append(dialog)
    dialog.finished.connect(lambda: _dialogs.remove(dialog))
    dialog.show()
