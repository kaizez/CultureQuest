import requests, time, os, tempfile, json
<<<<<<< Updated upstream
from models import ChallengeResponse
from flask import current_app
from db import db_session
=======
from .models import ChallengeResponse
from flask import current_app
from .db import db_session
>>>>>>> Stashed changes

def scan_file_in_background(app, response_id):
    with app.app_context():
        response = db_session.get(ChallengeResponse, response_id)
        print(response)
        if not response or not response.file_content:
            print(f"Error: Could not find response or file content for {response_id}.")
            return
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{response.filename}") as temp_file:
            temp_filepath = temp_file.name
            temp_file.write(response.file_content)

        try:
            print(f"Starting background scan for response ID: {response_id}")
            analysis_id = upload_file_to_virustotal(temp_filepath)
            report = None
            report = None
            if analysis_id:
                report = get_file_analysis_report(analysis_id)
            
            
            response_to_update = db_session.get(ChallengeResponse, response_id)
            if response_to_update:
                if report:
                    response_to_update.virustotal_scan_results = json.dumps(report)
                
                response_to_update.status = 'COMPLETED'
                db_session.commit()
                print(f"Background scan for response {response_id} completed.")
            else:
                print(f"Error: Could not find response {response_id} after scan.")

        except Exception as e:
            print(f"Error in background file scan for response {response_id}: {e}")
            response_to_update = db_session.get(ChallengeResponse, response_id)
            if response_to_update:
                response_to_update.status = 'SCAN_FAILED'
                db_session.commit()
        
        finally:
            if os.path.exists(temp_filepath):
                os.remove(temp_filepath)
                print(f"Cleaned up temporary file: {temp_filepath}")

API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
def upload_file_to_virustotal(file_path):
    """Uploads a file to VirusTotal for scanning."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}

    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
        
        filename = os.path.basename(file_path)
        files = {"file": (filename, file_content)}
        
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()

        scan_result = response.json()
        analysis_id = scan_result.get("data", {}).get("id")
        if analysis_id:
            print(f"File uploaded successfully! Analysis ID: {analysis_id}")
            return analysis_id
        else:
            print(f"Error: Could not get analysis ID. Response: {scan_result}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file: {e}")
        return None
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None

def get_file_analysis_report(analysis_id):
    """Retrieves the analysis report for a given analysis ID."""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}

    while True:
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()

            report = response.json()
            status = report.get("data", {}).get("attributes", {}).get("status")

            if status == "completed":
                print("\nScan completed! Here's the report:")
                return report
            elif status == "queued" or status == "running":
                print(f"Scan status: {status}. Waiting for completion...")
                time.sleep(10)  
            else:
                print(f"Unexpected scan status: {status}. Response: {report}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving report: {e}")
            return None
        
ALLOWED_EXTENSIONS = {'jpeg', 'png', 'mp4', 'pdf', 'docx', 'xlsx', 'pptx'}
def allowed_file(filename):
    print(filename)
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


FILE_SIGNATURES = {
    'jpeg': (b'\xFF\xD8\xFF\xE0', b'\xFF\xD8\xFF\xE1', b'\xFF\xD8\xFF\xE8'),
    'png': (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',),
    'gif': (b'\x47\x49\x46\x38\x37\x61', b'\x47\x49\x46\x38\x39\x61'),
    'pdf': (b'\x25\x50\x44\x46\x2D',),
    'zip': (b'\x50\x4B\x03\x04', b'\x50\x4B\x05\x06', b'\x50\x4B\x07\x08'),
    'docx': (b'\x50\x4B\x03\x04',), 
    'xlsx': (b'\x50\x4B\x03\x04',),
    'pptx': (b'\x50\x4B\x03\x04',),
    'mp3': (b'\x49\x44\x33', b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2'), 
    'wav': (b'\x52\x49\x46\x46', b'\x57\x41\x56\x45'), 
    'mp4': (b'\x00\x00\x00\x18\x66\x74\x79\x70', b'\x66\x74\x79\x70\x69\x73\x6F\x6D'), 
    'exe': (b'\x4D\x5A',), 
}

def check_file_signature(file_stream):
    header_size = max(len(sig) for signatures in FILE_SIGNATURES.values() for sig in signatures) if FILE_SIGNATURES else 0
    header = file_stream.read(header_size + 10)  
    file_stream.seek(0)  

    for file_type, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if header.startswith(signature):
                return file_type
    return 'unknown'


def verify_recaptcha(token, action):
    secret = current_app.config['RECAPTCHA_SECRET_KEY']
    if not secret:
        print("Warning: RECAPTCHA_SECRET_KEY is not set. Skipping verification.")
        return True, 1.0 
    try:
        response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={
                'secret': secret,
                'response': token
            }
        )
        result = response.json()
        print(f"reCAPTCHA verification result: {result}") 

        
        if result.get('success') and result.get('action') == action and result.get('score', 0) > 0.5:
            return True, result.get('score')
        else:
            
            return True, 1.0 
    except Exception as e:
        print(f"Error verifying reCAPTCHA: {e}")
        return True, 1.0 



initial_challenges_data = {
    "new_challenges": [
        {
            "status": "NEW",
            "title": "Learn How to Crochet from an Elder",
            "difficulty": "Beginner",
            "description": "Embark on a heartwarming journey to learn the beautiful art of crocheting. Spend quality time with an elderly mentor, learn stitches, and create a lovely piece together. This challenge is about sharing skills and building connections across generations.",
            "duration": "3 days",
            "category": "Creative Arts",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        },
        {
            "status": None,
            "title": "Learn a new dialect",
            "difficulty": "Intermediate",
            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut vestibulum id libero sit amet mollis.",
            "duration": "1 week",
            "category": "Life Skills",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        },
        {
            "status": "NEW",
            "title": "Play with a new instrument",
            "difficulty": "Advanced",
            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut vestibulum id libero sit amet mollis.",
            "duration": "2 weeks",
            "category": "Creative Arts",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        },
    ],
    "current_challenges": [
        {
            "status": "IN PROGRESS",
            "title": "Learn about the art of letter writing",
            "difficulty": "Intermediate",
            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut vestibulum id libero sit amet mollis.",
            "progress_percent": 65,
            "duration_left": "3 days left",
            "xp": 250,
            "category": "Life Skills",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        },
        {
            "status": "IN PROGRESS",
            "title": "Learn to assemble a furniture yourself",
            "difficulty": "Advanced",
            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut vestibulum id libero sit amet mollis.",
            "progress_percent": 90,
            "duration_left": "1 day left",
            "xp": 500,
            "category": "Life Skills",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        },
        {
            "status": "IN PROGRESS",
            "title": "Learn to cook traditional malay dishes",
            "difficulty": "Intermediate",
            "description": "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut vestibulum id libero sit amet mollis.",
            "progress_percent": 40,
            "duration_left": "5 days left",
            "xp": 350,
            "category": "Creative Arts",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        },
    ],
    "done_challenges": [
        {
            "status": "COMPLETED",
            "title": "Create a Digital Story with Your Elder",
            "difficulty": "Intermediate",
            "description": "You successfully created a beautiful digital story, preserving memories and sharing narratives! Congratulations on completing this heartwarming challenge.",
            "progress_percent": 100,
            "duration_left": "Completed",
            "xp": 400,
            "category": "Digital Literacy",
            "what_you_will_do": [],
            "requirements": [],
            "comments": [],
        }
    ]
}