#!/usr/bin/env python3
"""
Clear Uploads Folder Script
===========================
This script safely deletes ALL files in the static/uploads folder.
It will NOT affect any other folders or files in your project.

IMPORTANT: This action is irreversible. Make sure you have a backup if needed.
"""

import os
import sys

UPLOADS_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')

def confirm_action():
    """Ask for user confirmation before clearing files."""
    print("\n" + "="*60)
    print("⚠️  UPLOADS FOLDER CLEAR OPERATION ⚠️")
    print("="*60)
    print(f"Folder to be cleared: {UPLOADS_FOLDER}")
    print("\n⚠️  This action is IRREVERSIBLE!")
    print("="*60)
    response = input("\nType 'CLEAR UPLOADS' to confirm (anything else to cancel): ")
    return response == 'CLEAR UPLOADS'

def clear_uploads_folder():
    """Delete all files in the uploads folder."""
    if not os.path.exists(UPLOADS_FOLDER):
        print(f"❌ Folder not found: {UPLOADS_FOLDER}")
        return False

    files = [f for f in os.listdir(UPLOADS_FOLDER) if os.path.isfile(os.path.join(UPLOADS_FOLDER, f))]
    print(f"\nFound {len(files)} files to delete...")

    if not files:
        print("✅ No files found. Nothing to clear.")
        return True

    deleted_count = 0
    for filename in files:
        file_path = os.path.join(UPLOADS_FOLDER, filename)
        try:
            os.remove(file_path)
            deleted_count += 1
        except Exception as e:
            print(f"❌ Failed to delete {filename}: {str(e)}")

    print(f"✅ Successfully deleted {deleted_count} files from uploads folder")
    return True

def main():
    print("Uploads Folder Clear Script")
    print("==========================")

    if not confirm_action():
        print("❌ Operation cancelled by user")
        sys.exit(0)

    if clear_uploads_folder():
        print("\n🎉 Uploads folder clear operation completed successfully!")
    else:
        print("\n❌ Uploads folder clear operation failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()