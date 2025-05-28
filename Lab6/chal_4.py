#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import sys

# --- Configuration ---
OFFSET_RETURN_SITE_FROM_BASE = 0x9c83

context.arch = 'amd64'
context.os = 'linux'
context.endian = "little"
# context.log_level = 'debug' # 取消註解以獲得更詳細的 pwntools 日誌