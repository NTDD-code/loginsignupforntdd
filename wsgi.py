import sys
import os
from flask import Flask

# Thay đổi đường dẫn đến thư mục chứa ứng dụng của bạn
sys.path.insert(0, 'app.py')

from app import app as application
