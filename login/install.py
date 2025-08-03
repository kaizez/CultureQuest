#!/usr/bin/env python3
"""
Simple installation script for CultureQuest
"""

import subprocess
import sys

def install_requirements():
    """Install required packages"""
    print("Installing required packages...")
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])
        print("✅ Packages installed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error installing packages: {e}")
        return False

def test_connection():
    """Test database connection"""
    print("Testing database connection...")
    try:
        subprocess.check_call([sys.executable, 'test_mysql_connection.py'])
        return True
    except subprocess.CalledProcessError:
        print("❌ Database connection test failed")
        return False

def main():
    print("=== CultureQuest Installation ===")
    print(f"Python version: {sys.version}")
    print()
    
    # Install packages
    if not install_requirements():
        return False
    
    print()
    
    # Test connection
    if not test_connection():
        print("⚠️  Database connection failed, but you can still try running the app")
    
    print()
    print("🎉 Installation complete!")
    print("To start the application, run: python app.py")
    
    return True

if __name__ == '__main__':
    main()