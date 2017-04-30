#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lief
import unittest
import logging
import os
import sys
import stat
import re
import subprocess
import tempfile
import shutil
import time
import ctypes

from subprocess import Popen

from unittest import TestCase
from utils import get_sample

class TestHooking(TestCase):
    def setUp(self):
        self.logger = logging.getLogger(__name__)
        self.tmp_dir = tempfile.mkdtemp(suffix='_lief_test_hooking')
        self.logger.debug("temp dir: {}".format(self.tmp_dir))

        if sys.platform.startswith("win32"):
            SEM_NOGPFAULTERRORBOX = 0x0002 # From MSDN
            ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX);
            subprocess_flags = 0x8000000 #win32con.CREATE_NO_WINDOW?


    def test_hook_64(self):
        sample_path = get_sample('PE/PE64_x86-64_binary_HelloWorld.exe')
        output      = os.path.join(self.tmp_dir, "pe64_hooking.exe")

        hello = lief.parse(sample_path)
        code = [72, 199, 193, 0, 0, 0, 0, 72, 137, 210, 73, 184, 0, 144, 0, 64, 1, 0, 0, 0, 72, 184, 228, 163, 0, 64, 1, 0, 0, 0, 255, 16, 72, 199, 193, 0, 0, 0, 0, 72, 184, 212, 163, 0, 64, 1, 0, 0, 0, 255, 16, 195]

        title   = "LIEF is awesome\0"

        data =  list(map(ord, title))

        section_text                 = lief.PE.Section(".htext")
        section_text.content         = code
        section_text.virtual_address = 0x8000
        section_text.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

        section_data                 = lief.PE.Section(".hdata")
        section_data.content         = data
        section_data.virtual_address = 0x9000
        section_data.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA | lief.PE.SECTION_CHARACTERISTICS.MEM_READ

        hello.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
        hello.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.NX_COMPAT

        section_text = hello.add_section(section_text)
        section_data = hello.add_section(section_data)

        kernel32 = hello.get_import("KERNEL32.dll")
        kernel32.add_entry("ExitProcess")
        #
        user32 = hello.add_library("user32.dll")
        user32.add_entry("MessageBoxA")

        ExitProcess_addr = hello.predict_function_rva("KERNEL32.dll", "ExitProcess")
        MessageBoxA_addr = hello.predict_function_rva("user32.dll", "MessageBoxA")
        self.logger.debug("Address of 'MessageBoxA': 0x{:06x} ".format(MessageBoxA_addr))
        self.logger.debug("Address of 'ExitProcess': 0x{:06x} ".format(ExitProcess_addr))

        hello.hook_function("__acrt_iob_func", section_text.virtual_address + hello.optional_header.imagebase)

        builder = lief.PE.Builder(hello)
        builder.build_imports(True).patch_imports(True)
        builder.build()

        builder.write(output)

        st = os.stat(output)
        os.chmod(output, st.st_mode | stat.S_IEXEC)

        if sys.platform.startswith("win32"):
            p = Popen(["START", output, "foo"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            time.sleep(3)

            q = Popen(["taskkill", "/im", "pe64_hooking.exe"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

            stdout, _ = p.communicate()
            self.logger.debug(stdout.decode("utf8"))

            stdout, _ = q.communicate()
            self.logger.debug(stdout.decode("utf8"))

            self.assertEqual(q.returncode, 0)

        #self.assertIsNotNone(re.search(r'LIEF is Working', stdout.decode("utf8")))


    def tearDown(self):
        # Delete it
        if os.path.isdir(self.tmp_dir):
            shutil.rmtree(self.tmp_dir)

if __name__ == '__main__':

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    root_logger.addHandler(ch)

    unittest.main(verbosity=2)
