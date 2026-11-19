"""Binary Ninja sidebar for extracted TTD API calls."""
import ctypes
import os
import sys

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QTimer, QProcess, QThread, Signal
from PySide6.QtWidgets import (QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
                               QFileDialog, QTableView, QTextEdit, QLabel, QMessageBox, QWidget, QTabWidget, QProgressBar)

from binaryninjaui import Sidebar, SidebarWidget, SidebarWidgetType, SidebarWidgetLocation

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
                  ', '.join(str(param) for param in self.report.parameters(call)), hex(call.ret), hex(call.return_address))
        return values[index.column()]


class QueryWorker(QThread):
    completed = Signal(int, object, str)

    def __init__(self, path, expression, generation, parent=None):
        super().__init__(parent)
        self.path = path
        self.expression = expression
        self.generation = generation

    def run(self):
        rows = []
        try:
            with Report(self.path) as report:
                for index in report.query(self.expression, self.isInterruptionRequested):
                    if self.isInterruptionRequested():
                        return
                    rows.append(index)
            self.completed.emit(self.generation, rows, '')
        except Exception as error:
            self.completed.emit(self.generation, None, str(error))


class BehaviorPane(QWidget):
    def __init__(self, bv, parent=None):
        super().__init__(parent)
        self.bv = bv
        self.sidebar = parent
        self.report = None
        self.process = None
        self._query_generation = 0
        self._workers = set()
        layout = QVBoxLayout(self)
        buttons = QHBoxLayout()
        load = QPushButton('Load Report…')
        load.clicked.connect(self.load_report)
        buttons.addWidget(load)
        if sys.platform == 'win32':
            extract = QPushButton('Extract…')
            extract.clicked.connect(self.extract)
            buttons.addWidget(extract)
            self.cancel_button = QPushButton('Cancel')
            self.cancel_button.setEnabled(False)
            self.cancel_button.clicked.connect(self.cancel_extraction)
            buttons.addWidget(self.cancel_button)
        self.status = QLabel('Open a .ttdb report')
        buttons.addWidget(self.status, 1)
        layout.addLayout(buttons)
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)
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
        self.sidebar.install_report(path)

    def _load_report(self, path):
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
        self._query_generation += 1
        generation = self._query_generation
        for worker in self._workers:
            worker.requestInterruption()
        expression = self.filter.text().strip()
        if not expression:
            self.model.set_rows(None)
            self.status.setText(f'{self.report.call_count:,} calls')
            return
        worker = QueryWorker(str(self.report.path), expression, generation, self)
        self._workers.add(worker)
        worker.completed.connect(self.finish_filter)
        worker.finished.connect(lambda: self._workers.discard(worker))
        worker.finished.connect(worker.deleteLater)
        self.status.setText('Filtering…')
        worker.start()

    def finish_filter(self, generation, rows, error):
        if generation != self._query_generation or not self.report:
            return
        if error:
            self.status.setText(error)
            return
        self.model.set_rows(rows)
        self.status.setText(f'{len(rows):,} / {self.report.call_count:,} calls')

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

    def active_trace_path(self):
        try:
            from debugger import DebuggerController
            from debugger import _debuggercore as dbgcore
            from binaryninja import Settings
            from binaryninja import _binaryninjacore as bncore
            controller = DebuggerController(self.bv)
            if not controller.is_ttd:
                return None
            pointer = dbgcore.BNDebuggerGetAdapterSettings(controller.handle)
            if not pointer:
                return None
            settings = Settings(handle=ctypes.cast(pointer, ctypes.POINTER(bncore.BNSettings)))
            path = settings.get_string('launch.trace_path', self.bv)
            return path if os.path.isfile(path) else None
        except Exception:
            return None

    def extract(self):
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            return
        trace = self.active_trace_path()
        if not trace:
            trace, _ = QFileDialog.getOpenFileName(self, 'Select TTD trace', '', 'TTD traces (*.run)')
        if not trace:
            return
        output = os.path.splitext(trace)[0] + '.ttdb'
        if os.path.exists(output):
            choice = QMessageBox.question(self, 'TTD Behavior',
                                          'A report already exists. Load it?',
                                          QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                                          QMessageBox.Yes)
            if choice == QMessageBox.Yes:
                self.load_report(output)
                return
            if choice == QMessageBox.Cancel:
                return
        if not os.access(os.path.dirname(output), os.W_OK):
            output, _ = QFileDialog.getSaveFileName(self, 'Save TTD report', output, 'TTD reports (*.ttdb)')
            if not output:
                return
        try:
            args = command(trace, output)
            args.append('--cancel-on-stdin')
        except Exception as error:
            QMessageBox.critical(self, 'Extraction failed', str(error))
            return
        self._output = output
        self._stderr = bytearray()
        self.process = QProcess(self)
        self.process.setWorkingDirectory(os.path.dirname(args[0]))
        self.process.readyReadStandardError.connect(self.read_progress)
        self.process.finished.connect(self.finish_extraction)
        self.process.errorOccurred.connect(self.extraction_error)
        self.process.start(args[0], args[1:])
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.cancel_button.setEnabled(True)
        self.status.setText('Sweeping trace…')

    def extraction_error(self, error):
        if error == QProcess.ProcessError.FailedToStart:
            self.progress.setVisible(False)
            self.cancel_button.setEnabled(False)
            QMessageBox.critical(self, 'Extraction failed', self.process.errorString())
            self.process.deleteLater()
            self.process = None

    def read_progress(self):
        self._stderr.extend(bytes(self.process.readAllStandardError()))
        while b'\n' in self._stderr:
            line, _, remainder = self._stderr.partition(b'\n')
            self._stderr = bytearray(remainder)
            line = line.decode('utf-8', 'replace').strip()
            if line.startswith('[progress]'):
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        self.progress.setValue(round(float(parts[1])))
                        self.status.setText(f'Sweeping trace: {parts[2]} calls')
                    except ValueError:
                        pass
            elif line.startswith('[phase]'):
                self.status.setText({'[phase] sweep': 'Sweeping trace…',
                                     '[phase] strings': 'Recovering strings…',
                                     '[phase] write': 'Writing report…'}.get(line, line))
                if line != '[phase] sweep':
                    self.progress.setRange(0, 0)
                    self.cancel_button.setEnabled(False)

    def cancel_extraction(self):
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.write(b'cancel\n')
            self.cancel_button.setEnabled(False)
            self.status.setText('Cancelling; writing partial report…')

    def finish_extraction(self, exit_code, exit_status):
        if self.process is None:
            return
        self.read_progress()
        self.progress.setVisible(False)
        self.progress.setRange(0, 100)
        self.cancel_button.setEnabled(False)
        if exit_code == 0 and os.path.isfile(self._output):
            self.load_report(self._output)
        else:
            QMessageBox.critical(self, 'Extraction failed',
                                 self._stderr.decode('utf-8', 'replace')[-4000:] or f'Exit code {exit_code}')
        self.process.deleteLater()
        self.process = None

    def closeEvent(self, event):
        for worker in self._workers:
            worker.requestInterruption()
        for worker in self._workers:
            worker.wait()
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()
        if self.report:
            self.report.close()
        super().closeEvent(event)


class BehaviorSidebar(SidebarWidget):
    def __init__(self, frame, data):
        super().__init__('TTD Behavior')
        self.data = data
        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.update_title)
        add = QPushButton('+')
        add.setToolTip('Add behavior tab')
        add.clicked.connect(self.add_tab)
        self.tabs.setCornerWidget(add)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.tabs)
        self.add_tab()

    def add_tab(self):
        previous = self.tabs.currentWidget()
        pane = BehaviorPane(self.data, self)
        index = self.tabs.addTab(pane, 'Behavior')
        if previous is not None and previous.report is not None:
            pane._load_report(str(previous.report.path))
        pane.filter.textChanged.connect(lambda: self.update_title())
        self.tabs.setCurrentIndex(index)

    def install_report(self, path):
        for index in range(self.tabs.count()):
            self.tabs.widget(index)._load_report(path)

    def close_tab(self, index):
        if self.tabs.count() == 1:
            return
        pane = self.tabs.widget(index)
        self.tabs.removeTab(index)
        pane.close()
        pane.deleteLater()

    def closeEvent(self, event):
        for index in range(self.tabs.count()):
            self.tabs.widget(index).close()
        super().closeEvent(event)

    def update_title(self, *_):
        index = self.tabs.currentIndex()
        if index >= 0:
            pane = self.tabs.widget(index)
            title = pane.filter.text().strip() or 'Behavior'
            self.tabs.setTabText(index, title[:24])


class BehaviorSidebarType(SidebarWidgetType):
    def __init__(self):
        from PySide6.QtGui import QImage, QPainter, QColor, QFont
        icon = QImage(56, 56, QImage.Format_ARGB32)
        icon.fill(0)
        painter = QPainter(icon)
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont('', 40))
        painter.drawText(icon.rect(), Qt.AlignCenter, 'T')
        painter.end()
        super().__init__(icon, 'TTD Behavior')

    def createWidget(self, frame, data):
        return BehaviorSidebar(frame, data)

    def defaultLocation(self):
        return SidebarWidgetLocation.RightContent


Sidebar.addSidebarWidgetType(BehaviorSidebarType())
