# ZTE-MC-WINGUI

**Program**

**Compiled version is in releases !**

![enter image description here](https://raw.githubusercontent.com/Kajkac/ZTE-MC-WINGUI/main/img/1.png)

![enter image description here](https://raw.githubusercontent.com/Kajkac/ZTE-MC-WINGUI/main/img/2.png)

![enter image description here](https://raw.githubusercontent.com/Kajkac/ZTE-MC-WINGUI/main/img/3.png)

**BUILD**

Python Project to Standalone Executable using PyInstaller
This documentation provides step-by-step instructions on how to convert your Python project into a standalone executable for Windows using PyInstaller.

**Project Structure**
Ensure your project directory has the following structure:

project/
├── config.ini
├── mc.py
├── zte.py
├── main.spec

config.ini: Configuration file
mc.py: Core functionality script
zte.py: Tkinter GUI script (main entry point)
main.spec: PyInstaller specification file

**Requirements**

Python 3.x
PyInstaller
Required Python packages:
requests
ttkbootstrap
hashlib
datetime
binascii
urllib3
json
tkinter
configparser
os
re

***Installation Steps***

**1. Install PyInstaller**
First, ensure PyInstaller is installed. You can install it via pip:

pip install pyinstaller

**2. Create a Virtual Environment (Optional but Recommended)**
To avoid conflicts with other Python packages, create a virtual environment:

python -m venv myenv
source myenv/bin/activate  # On Windows, use `myenv\Scripts\activate`
pip install pyinstaller requests ttkbootstrap

**3. Create the Spec File**
Use a main.spec file in your project directory with the following content

**4. Build the Executable**
Navigate to your project directory and run PyInstaller with the spec file:

pyinstaller main.spec

**5. Locate the Executable**
After the build process completes, you will find the standalone executable in the dist directory:

project/
├── dist/
│   └── zte.exe
├── build/
├── config.ini
├── mc.py
├── zte.py
└── main.spec

**6. Test the Executable**
Navigate to the dist directory and run zte.exe to ensure it works correctly.
