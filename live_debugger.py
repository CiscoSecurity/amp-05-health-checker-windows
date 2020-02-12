'''
This section provides live feedback on what AMP is processing on the system.
'''
from pathlib import Path
import re
from string import Template
import PySimpleGUI as sg
from data import Data

class LivePathAndProcess:
    '''
    This class is the instance conducing the live processing of AMP operations.
    '''
    def __init__(self, key, format="$time_ || $process_ || $file_\n", size=(100, 10)):
        root_path = "C:/Program Files/Cisco/AMP"
        self.p = Path(root_path)
        self.template = format
        self.size = size
        amp_version = Data.get_version(self)
        self.matches, self.filtered = self.add_to_set([], [], amp_version, self.p)
        rev = list(self.filtered)
        rev.reverse()
        self.times = list(map(lambda i: i[0], rev))
        self.processes = list(map(lambda i: i[2], rev))
        self.files = list(map(lambda i: i[1], rev))
        formatted = ""
        self.template = Template(self.template)
        for line in zip(self.times, self.processes, self.files):
            time_, process_, file_ = line
            to_add = self.template.substitute(time_=time_, process_=process_, file_=file_)
            formatted += to_add
        self.key = key
        self.layout = sg.Multiline(formatted, size=size, key=self.key)

    def parse_it(self, line):
        """
        Takes a regular sfc.exe.log line and returns parsed-for-publication formatting.
        """

        reg_1 = r"(\w\w\w \d\d \d\d:\d\d:\d\d).*\\\\\?\\(.*)\(\\\\\?\\.*\\\\\?\\(.*)"
        reg = re.findall(reg_1, line)
        if reg:
            return list(reg[0])
            # return "TIME:  {reg[0][0]}\nFILE:  {reg[0][1]}\nPROCESS:  {reg[0][2]}\n\n"

    def add_to_set(self, the_list, filtered_list, version, path, filename="events.log"):
        """
        Takes the master list of all sfc log lines and filtered list of
        filescan/processes already found (formatted for output),
        scans through the last 10k sfc.exe.log lines for any new instances,
        returns updated lists
        """

        reg_1 = r"\w\w\w \d\d \d\d:\d\d:\d\d.*\\\\\?\\.*\\\\\?\\.*\\\\\?\\.*"
        sfc_logs = list(path.glob("{}/sfc.exe.log".format(version)))
        if sfc_logs:
            with open(sfc_logs[0]) as file:
                file_read = file.readlines()[-1000:]
            for i in file_read:
                if "Event::Handle" in i:
                    reg = re.findall(reg_1, i)
                    if reg:
                        if reg[0] not in the_list:
                            the_list.append(reg[0])
                            filtered_list.append(self.parse_it(reg[0]))

        else:
            print("no sfc log")

        return the_list, filtered_list

    def update(self, window): #matches, filtered, amp_version, p, window, key):
        """
        Updates
        """

        amp_version = Data.get_version(self)
        self.matches, self.filtered = self.add_to_set(self.matches, self.filtered, \
            amp_version, self.p)
        rev = list(self.filtered)
        rev.reverse()
        self.times = list(map(lambda i: i[0], rev))
        self.processes = list(map(lambda i: i[2], rev))
        self.files = list(map(lambda i: i[1], rev))
        formatted = ""
        for line in zip(self.times, self.processes, self.files):
            time_, process_, file_ = line
            to_add = self.template.substitute(time_=time_, process_=process_, file_=file_)
            formatted += to_add
            window.Element(self.key).Update(formatted)

def main():
    '''
    Main function for live debugger.
    '''
    lppc = LivePathAndProcess("_output1") # template="$process_\n")

    layout = [
        [lppc.layout],
        [sg.Text("AMP CPU Usage: "), sg.Text("{:.1f}", key='_cpu')],
        [
            sg.Button("Pause"),
            sg.Button("Resume"),
            sg.FileSaveAs("Save As", file_types=(("Log File", "*.log"),)),
            sg.Button("Cancel"),
            sg.Text("Status: RUNNING", key="_running"),
        ]
    ]

    window = sg.Window("Live File/Process Monitoring", layout)

    running = True
    to_save = ""
    while True:
        event, values = window.Read(timeout=2000)
        if event in (None, "Cancel"):
            break
        elif event == "Pause":
            running = False
            window.Element("_running").Update("Status: PAUSED")
        elif event == "Resume":
            running = True
            window.Element("_running").Update("Status: RUNNING")
        if values.get("Save As") != to_save:
            to_save = values.get("Save As")
            with open(values.get("Save As"), "w") as file:
                file.write(values.get(lppc.key))
        if running:
            lppc.update(window)

    window.close()

if __name__ == "__main__":
    main()
