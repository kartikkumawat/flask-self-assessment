from flask import Flask, request, jsonify, url_for
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson.objectid import ObjectId
from datetime import datetime, timedelta
import uuid
import re
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
import os
from dotenv import load_dotenv
import bleach
from flask_cors import CORS
import secrets
import string

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Security configurations
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)))
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/edulearn')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)))
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-password')
app.config['MAIL_USE_TLS'] = True
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32)))

# Initialize extensions
mongo = PyMongo(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database collections
users = mongo.db.users
quizzes = mongo.db.quizzes
questions = mongo.db.questions
attempts = mongo.db.attempts

# Email utility functions
def send_email(to, subject, template):
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = to
    
    msg.attach(MIMEText(template, 'html'))
    
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.ehlo()
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(app.config['MAIL_USERNAME'], to, msg.as_string())
        server.close()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_confirmation_token(email):
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
        return email
    except SignatureExpired:
        return False
    except:
        return False

# Security helper functions
def sanitize_input(data):
    """Sanitize input to prevent XSS attacks"""
    if isinstance(data, dict):
        return {k: sanitize_input(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_input(i) for i in data]
    elif isinstance(data, str):
        return bleach.clean(data)
    else:
        return data

def validate_email(email):
    """Validate email format"""
    pattern = r'^\S+@\S+\.\S+$'
    return re.match(pattern, email) is not None

def validate_date(date_str):
    """Validate date format (YYYY-MM-DD)"""
    try:
        datetime.strptime(date_str, '%Y-%m-%d')
        return True
    except ValueError:
        return False

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = sanitize_input(request.get_json())
    
    # Validate required fields
    required_fields = ['name', 'email', 'password', 'location', 'dob', 'roll_number']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    # Validate email format
    if not validate_email(data['email']):
        return jsonify({"error": "Invalid email format"}), 400
    
    # Validate date of birth format
    if not validate_date(data['dob']):
        return jsonify({"error": "Invalid date format for date of birth. Use YYYY-MM-DD"}), 400
    
    # Check if email already exists
    if users.find_one({"email": data['email']}):
        return jsonify({"error": "Email already registered"}), 409
    
    # Check if roll number already exists
    if users.find_one({"roll_number": data['roll_number']}):
        return jsonify({"error": "Roll number already exists"}), 409
    
    # Hash password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Create user object
    user = {
        "name": data['name'],
        "email": data['email'],
        "password": hashed_password,
        "location": data['location'],
        "dob": data['dob'],
        "roll_number": data['roll_number'],
        "unique_id": str(uuid.uuid4()),
        "created_at": datetime.utcnow(),
        "is_verified": False,
        "preferences": {
            "quiz_frequency": "weekly",
            "difficulty_preference": "medium"
        }
    }
    
    # Insert user to database
    result = users.insert_one(user)
    
    # Generate confirmation token
    token = generate_confirmation_token(data['email'])
    
    # Create verification URL
    verify_url = url_for('verify_email', token=token, _external=True)
    
    # Email template
    html = f"""
    <html>
    <head></head>
    <body>
        <h2>Welcome to EduLearn!</h2>
        <p>Hi {data['name']},</p>
        <p>Please confirm your email address by clicking the link below:</p>
        <p><a href="{verify_url}">Verify Email</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not register for EduLearn, please ignore this email.</p>
    </body>
    </html>
    """
    
    # Send verification email
    if send_email(data['email'], "Verify your EduLearn account", html):
        return jsonify({
            "message": "Registration successful. Verification email sent.",
            "user_id": str(result.inserted_id)
        }), 201
    else:
        users.delete_one({"_id": result.inserted_id})
        return jsonify({"error": "Failed to send verification email. Registration cancelled."}), 500

@app.route('/verify-email/<token>', methods=['GET'])
def verify_email(token):
    email = confirm_token(token)
    
    if not email:
        return jsonify({"error": "The verification link is invalid or has expired."}), 400
    
    user = users.find_one({"email": email})
    
    if not user:
        return jsonify({"error": "User not found."}), 404
    
    if user['is_verified']:
        return jsonify({"message": "Account already verified. Please login."}), 200
    
    users.update_one({"email": email}, {"$set": {"is_verified": True}})
    
    return jsonify({"message": "Email verification successful! You can now login."}), 200

@app.route('/login', methods=['POST'])
def login():
    data = sanitize_input(request.get_json())
    
    if not data.get('email') or not data.get('password'):
        return jsonify({"error": "Email and password are required"}), 400
    
    user = users.find_one({"email": data['email']})
    
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401
    
    if not user['is_verified']:
        return jsonify({"error": "Email not verified. Please check your inbox."}), 401
    
    if bcrypt.check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=str(user['_id']))
        return jsonify({
            "message": "Login successful",
            "token": access_token,
            "user": {
                "id": str(user['_id']),
                "name": user['name'],
                "email": user['email'],
                "roll_number": user['roll_number']
            }
        }), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    
    try:
        user = users.find_one({"_id": ObjectId(current_user_id)})
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Remove password from response
        user.pop('password', None)
        user['_id'] = str(user['_id'])
        
        return jsonify({"user": user}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = sanitize_input(request.get_json())
    
    updateable_fields = ['name', 'location', 'dob', 'preferences']
    update_data = {k: v for k, v in data.items() if k in updateable_fields}
    
    if 'dob' in update_data and not validate_date(update_data['dob']):
        return jsonify({"error": "Invalid date format for date of birth. Use YYYY-MM-DD"}), 400
    
    try:
        users.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$set": update_data}
        )
        
        return jsonify({"message": "Profile updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/questions', methods=['POST'])
@jwt_required()
def add_question():
    current_user_id = get_jwt_identity()
    data = sanitize_input(request.get_json())
    
    required_fields = ['subject', 'question_text', 'options', 'correct_answer', 'difficulty']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    if not isinstance(data['options'], list) or len(data['options']) < 2:
        return jsonify({"error": "Options must be a list with at least 2 items"}), 400
    
    if data['correct_answer'] not in data['options']:
        return jsonify({"error": "Correct answer must be one of the options"}), 400
    
    if data['difficulty'] not in ['easy', 'medium', 'hard']:
        return jsonify({"error": "Difficulty must be one of: easy, medium, hard"}), 400
    
    question = {
        "subject": data['subject'],
        "question_text": data['question_text'],
        "options": data['options'],
        "correct_answer": data['correct_answer'],
        "difficulty": data['difficulty'],
        "created_by": ObjectId(current_user_id),
        "created_at": datetime.utcnow()
    }
    
    result = questions.insert_one(question)
    
    return jsonify({
        "message": "Question added successfully",
        "question_id": str(result.inserted_id)
    }), 201

@app.route('/questions', methods=['GET'])
@jwt_required()
def get_questions():
    subject = request.args.get('subject')
    difficulty = request.args.get('difficulty')
    
    query = {}
    if subject:
        query['subject'] = subject
    if difficulty:
        query['difficulty'] = difficulty
    
    all_questions = list(questions.find(query))
    
    # Convert ObjectId to string
    for question in all_questions:
        question['_id'] = str(question['_id'])
        question['created_by'] = str(question['created_by'])
    
    return jsonify({"questions": all_questions}), 200

@app.route('/generate-quiz', methods=['POST'])
@jwt_required()
def generate_quiz():
    current_user_id = get_jwt_identity()
    data = sanitize_input(request.get_json())
    
    required_fields = ['subject', 'difficulty', 'question_count', 'time_limit']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    if data['difficulty'] not in ['easy', 'medium', 'hard', 'mixed']:
        return jsonify({"error": "Difficulty must be one of: easy, medium, hard, mixed"}), 400
    
    if not isinstance(data['question_count'], int) or data['question_count'] < 1:
        return jsonify({"error": "Question count must be a positive integer"}), 400
    
    if not isinstance(data['time_limit'], int) or data['time_limit'] < 1:
        return jsonify({"error": "Time limit must be a positive integer (minutes)"}), 400
    
    # Build query for questions
    query = {"subject": data['subject']}
    if data['difficulty'] != 'mixed':
        query['difficulty'] = data['difficulty']
    
    # Find questions matching criteria
    available_questions = list(questions.find(query))
    
    if len(available_questions) < data['question_count']:
        return jsonify({
            "error": f"Not enough questions available. Found {len(available_questions)}, needed {data['question_count']}"
        }), 400
    
    # Randomly select questions
    selected_questions = random.sample(available_questions, data['question_count'])
    
    # Create quiz object
    quiz = {
        "title": f"{data['subject']} {data['difficulty']} Quiz",
        "subject": data['subject'],
        "difficulty": data['difficulty'],
        "created_by": ObjectId(current_user_id),
        "created_at": datetime.utcnow(),
        "time_limit_minutes": data['time_limit'],
        "questions": [str(q['_id']) for q in selected_questions],
        "shareable": data.get('shareable', True),
        "share_links": {}
    }
    
    # Generate shareable links if requested
    if quiz['shareable']:
        share_id = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        quiz['share_links'] = {
            "direct": f"/quiz/{share_id}",
            "whatsapp": f"https://wa.me/?text=Try this quiz: /quiz/{share_id}",
            "twitter": f"https://twitter.com/intent/tweet?text=Try this quiz: /quiz/{share_id}",
            "facebook": f"https://www.facebook.com/sharer/sharer.php?u=/quiz/{share_id}",
            "instagram": f"/quiz/{share_id}"  # For copy-paste as Instagram doesn't have direct sharing
        }
        quiz['share_id'] = share_id
    
    # Save quiz to database
    result = quizzes.insert_one(quiz)
    
    # Format question details for response
    quiz_details = []
    for q in selected_questions:
        quiz_details.append({
            "id": str(q['_id']),
            "question_text": q['question_text'],
            "subject": q['subject'],
            "difficulty": q['difficulty']
        })
    
    return jsonify({
        "message": "Quiz generated successfully",
        "quiz_id": str(result.inserted_id),
        "quiz_details": quiz_details,
        "share_links": quiz.get('share_links', {})
    }), 201

@app.route('/quiz/<quiz_id>', methods=['GET'])
@jwt_required()
def get_quiz(quiz_id):
    try:
        quiz = quizzes.find_one({"_id": ObjectId(quiz_id)})
    except:
        # Try by share_id if not found by ObjectId
        quiz = quizzes.find_one({"share_id": quiz_id})
    
    if not quiz:
        return jsonify({"error": "Quiz not found"}), 404
    
    # Convert ObjectId to string
    quiz['_id'] = str(quiz['_id'])
    quiz['created_by'] = str(quiz['created_by'])
    
    # Get full question details
    quiz_questions = []
    for q_id in quiz['questions']:
        try:
            question = questions.find_one({"_id": ObjectId(q_id)})
            if question:
                question['_id'] = str(question['_id'])
                question['created_by'] = str(question['created_by'])
                quiz_questions.append(question)
        except:
            continue
    
    quiz['question_details'] = quiz_questions
    
    return jsonify({"quiz": quiz}), 200

@app.route('/attempt-quiz', methods=['POST'])
@jwt_required()
def attempt_quiz():
    current_user_id = get_jwt_identity()
    data = sanitize_input(request.get_json())
    
    required_fields = ['quiz_id', 'answers']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    try:
        quiz = quizzes.find_one({"_id": ObjectId(data['quiz_id'])})
    except:
        quiz = quizzes.find_one({"share_id": data['quiz_id']})
    
    if not quiz:
        return jsonify({"error": "Quiz not found"}), 404
    
    # Validate answers format
    if not isinstance(data['answers'], dict):
        return jsonify({"error": "Answers must be a dictionary with question IDs as keys"}), 400
    
    # Calculate results
    correct_count = 0
    question_results = {}
    
    for q_id in quiz['questions']:
        try:
            question = questions.find_one({"_id": ObjectId(q_id)})
            
            if not question:
                continue
            
            user_answer = data['answers'].get(q_id)
            correct = user_answer == question['correct_answer']
            
            if correct:
                correct_count += 1
            
            question_results[q_id] = {
                "question_text": question['question_text'],
                "user_answer": user_answer,
                "correct_answer": question['correct_answer'],
                "is_correct": correct
            }
        except:
            continue
    
    total_questions = len(quiz['questions'])
    score = (correct_count / total_questions) * 100 if total_questions > 0 else 0
    
    # Save attempt to database
    attempt = {
        "quiz_id": ObjectId(quiz['_id']),
        "user_id": ObjectId(current_user_id),
        "date": datetime.utcnow(),
        "answers": data['answers'],
        "question_results": question_results,
        "score": score,
        "correct_count": correct_count,
        "total_questions": total_questions,
        "time_taken_minutes": data.get('time_taken_minutes', quiz['time_limit_minutes'])
    }
    
    result = attempts.insert_one(attempt)
    
    return jsonify({
        "message": "Quiz submitted successfully",
        "attempt_id": str(result.inserted_id),
        "score": score,
        "correct_count": correct_count,
        "total_questions": total_questions,
        "question_results": question_results
    }), 201

@app.route('/progress', methods=['GET'])
@jwt_required()
def get_progress():
    current_user_id = get_jwt_identity()
    filter_type = request.args.get('filter', 'all')  # all, daily, weekly, monthly, yearly
    subject = request.args.get('subject')
    difficulty = request.args.get('difficulty')
    
    # Build date range filter
    date_filter = {}
    now = datetime.utcnow()
    
    if filter_type == 'daily':
        start_date = datetime(now.year, now.month, now.day)
        date_filter = {"date": {"$gte": start_date}}
    elif filter_type == 'weekly':
        start_date = now - timedelta(days=now.weekday())
        start_date = datetime(start_date.year, start_date.month, start_date.day)
        date_filter = {"date": {"$gte": start_date}}
    elif filter_type == 'monthly':
        start_date = datetime(now.year, now.month, 1)
        date_filter = {"date": {"$gte": start_date}}
    elif filter_type == 'yearly':
        start_date = datetime(now.year, 1, 1)
        date_filter = {"date": {"$gte": start_date}}
    
    # Query for user's attempts
    query = {"user_id": ObjectId(current_user_id)}
    query.update(date_filter)
    
    # If subject or difficulty specified, need to join with quizzes
    subject_difficulty_filter = {}
    if subject or difficulty:
        if subject:
            subject_difficulty_filter["subject"] = subject
        if difficulty:
            subject_difficulty_filter["difficulty"] = difficulty
    
    # Get all user attempts
    user_attempts = list(attempts.find(query))
    
    # Filter by subject/difficulty if needed
    if subject_difficulty_filter:
        filtered_attempts = []
        for attempt in user_attempts:
            try:
                quiz = quizzes.find_one({"_id": attempt["quiz_id"]})
                if quiz:
                    match = True
                    for key, value in subject_difficulty_filter.items():
                        if quiz.get(key) != value:
                            match = False
                            break
                    if match:
                        filtered_attempts.append(attempt)
            except:
                continue
        user_attempts = filtered_attempts
    
    # Format response
    progress_data = []
    for attempt in user_attempts:
        attempt['_id'] = str(attempt['_id'])
        attempt['quiz_id'] = str(attempt['quiz_id'])
        attempt['user_id'] = str(attempt['user_id'])
        
        try:
            quiz = quizzes.find_one({"_id": ObjectId(attempt['quiz_id'])})
            quiz_title = quiz['title'] if quiz else "Unknown Quiz"
            subject = quiz['subject'] if quiz else "Unknown"
            difficulty = quiz['difficulty'] if quiz else "Unknown"
        except:
            quiz_title = "Unknown Quiz"
            subject = "Unknown"
            difficulty = "Unknown"
        
        progress_data.append({
            "attempt_id": attempt['_id'],
            "quiz_id": attempt['quiz_id'],
            "quiz_title": quiz_title,
            "subject": subject,
            "difficulty": difficulty,
            "date": attempt['date'].strftime('%Y-%m-%d %H:%M:%S'),
            "score": attempt['score'],
            "correct_count": attempt['correct_count'],
            "total_questions": attempt['total_questions'],
            "time_taken_minutes": attempt.get('time_taken_minutes', 0)
        })
    
    # Calculate summary statistics
    total_quizzes = len(progress_data)
    avg_score = sum(a['score'] for a in progress_data) / total_quizzes if total_quizzes > 0 else 0
    total_questions = sum(a['total_questions'] for a in progress_data)
    total_correct = sum(a['correct_count'] for a in progress_data)
    
    subjects = {}
    for attempt in progress_data:
        subject = attempt['subject']
        if subject in subjects:
            subjects[subject]['quizzes'] += 1
            subjects[subject]['total_questions'] += attempt['total_questions']
            subjects[subject]['correct_questions'] += attempt['correct_count']
            subjects[subject]['total_score'] += attempt['score']
        else:
            subjects[subject] = {
                'quizzes': 1,
                'total_questions': attempt['total_questions'],
                'correct_questions': attempt['correct_count'],
                'total_score': attempt['score']
            }
    
    # Calculate average scores by subject
    for subject, data in subjects.items():
        data['avg_score'] = data['total_score'] / data['quizzes']
    
    summary = {
        "total_quizzes": total_quizzes,
        "avg_score": avg_score,
        "total_questions": total_questions,
        "total_correct": total_correct,
        "accuracy": (total_correct / total_questions) * 100 if total_questions > 0 else 0,
        "subjects": subjects
    }
    
    return jsonify({
        "progress": progress_data,
        "summary": summary
    }), 200

@app.route('/scheduled-quizzes', methods=['POST'])
@jwt_required()
def schedule_quiz():
    current_user_id = get_jwt_identity()
    data = sanitize_input(request.get_json())
    
    required_fields = ['frequency', 'subject', 'difficulty', 'question_count', 'time_limit']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400
    
    if data['frequency'] not in ['daily', 'weekly', 'monthly']:
        return jsonify({"error": "Frequency must be one of: daily, weekly, monthly"}), 400
    
    schedule = {
        "user_id": ObjectId(current_user_id),
        "frequency": data['frequency'],
        "subject": data['subject'],
        "difficulty": data['difficulty'],
        "question_count": data['question_count'],
        "time_limit": data['time_limit'],
        "created_at": datetime.utcnow(),
        "active": True
    }
    
    # Update user preferences
    users.update_one(
        {"_id": ObjectId(current_user_id)},
        {"$set": {"preferences.quiz_frequency": data['frequency']}}
    )
    
    result = mongo.db.scheduled_quizzes.insert_one(schedule)
    
    return jsonify({
        "message": "Quiz schedule created successfully",
        "schedule_id": str(result.inserted_id)
    }), 201

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = sanitize_input(request.get_json())
    
    if not data.get('email'):
        return jsonify({"error": "Email is required"}), 400
    
    user = users.find_one({"email": data['email']})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if user['is_verified']:
        return jsonify({"message": "Account already verified. Please login."}), 200
    
    # Generate confirmation token
    token = generate_confirmation_token(data['email'])
    
    # Create verification URL
    verify_url = url_for('verify_email', token=token, _external=True)
    
    # Email template
    html = f"""
    <html>
    <head></head>
    <body>
        <h2>Verify your EduLearn Account</h2>
        <p>Hi {user['name']},</p>
        <p>Please confirm your email address by clicking the link below:</p>
        <p><a href="{verify_url}">Verify Email</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not register for EduLearn, please ignore this email.</p>
    </body>
    </html>
    """
    
    # Send verification email
    if send_email(data['email'], "Verify your EduLearn account", html):
        return jsonify({
            "message": "Verification email resent successfully"
        }), 200
    else:
        return jsonify({"error": "Failed to send verification email"}), 500

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = sanitize_input(request.get_json())
    
    if not data.get('email'):
        return jsonify({"error": "Email is required"}), 400
    
    user = users.find_one({"email": data['email']})
    
    if not user:
        # For security reasons, don't reveal if email exists
        return jsonify({"message": "If this email is registered, a reset link will be sent"}), 200
    
    # Generate reset token
    token = serializer.dumps(data['email'], salt='password-reset-salt')
    
    # Create reset URL
    reset_url = url_for('reset_password', token=token, _external=True)
    
    # Email template
    html = f"""
    <html>
    <head></head>
    <body>
        <h2>Reset Your EduLearn Password</h2>
        <p>Hi {user['name']},</p>
        <p>To reset your password, please click the link below:</p>
        <p><a href="{reset_url}">Reset Password</a></p>
        <p>This link will expire in 1 hour.</p>
        <p>If you did not request this password reset, please ignore this email.</p>
    </body>
    </html>
    """
    
    # Send reset email
    if send_email(data['email'], "Reset your EduLearn password", html):
        return jsonify({
            "message": "If this email is registered, a reset link will be sent"
        }), 200
    else:
        return jsonify({"error": "Failed to send reset email"}), 500


@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        return jsonify({"error": "The reset link is invalid or has expired"}), 400
    
    data = sanitize_input(request.get_json())
    
    if not data.get('password'):
        return jsonify({"error": "New password is required"}), 400
    
    # Find user by email
    user = users.find_one({"email": email})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Hash new password
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # Update user password
    users.update_one(
        {"email": email},
        {"$set": {"password": hashed_password}}
    )
    
    return jsonify({"message": "Password has been reset successfully"}), 200

@app.route('/quizzes', methods=['GET'])
@jwt_required()
def get_user_quizzes():
    current_user_id = get_jwt_identity()
    
    user_quizzes = list(quizzes.find({"created_by": ObjectId(current_user_id)}))
    
    # Format response
    for quiz in user_quizzes:
        quiz['_id'] = str(quiz['_id'])
        quiz['created_by'] = str(quiz['created_by'])
    
    return jsonify({"quizzes": user_quizzes}), 200

@app.route('/attempt/<attempt_id>', methods=['GET'])
@jwt_required()
def get_attempt_details(attempt_id):
    current_user_id = get_jwt_identity()
    
    try:
        attempt = attempts.find_one({
            "_id": ObjectId(attempt_id),
            "user_id": ObjectId(current_user_id)
        })
    except:
        return jsonify({"error": "Attempt not found"}), 404
    
    if not attempt:
        return jsonify({"error": "Attempt not found"}), 404
    
    # Convert ObjectId to string
    attempt['_id'] = str(attempt['_id'])
    attempt['quiz_id'] = str(attempt['quiz_id'])
    attempt['user_id'] = str(attempt['user_id'])
    
    # Get quiz details
    try:
        quiz = quizzes.find_one({"_id": ObjectId(attempt['quiz_id'])})
        if quiz:
            quiz['_id'] = str(quiz['_id'])
            quiz['created_by'] = str(quiz['created_by'])
            attempt['quiz'] = quiz
    except:
        attempt['quiz'] = None
    
    return jsonify({"attempt": attempt}), 200

@app.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    data = sanitize_input(request.get_json())
    
    if not data.get('current_password') or not data.get('new_password'):
        return jsonify({"error": "Current password and new password are required"}), 400
    
    user = users.find_one({"_id": ObjectId(current_user_id)})
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    if not bcrypt.check_password_hash(user['password'], data['current_password']):
        return jsonify({"error": "Current password is incorrect"}), 401
    
    # Hash new password
    hashed_password = bcrypt.generate_password_hash(data['new_password']).decode('utf-8')
    
    # Update user password
    users.update_one(
        {"_id": ObjectId(current_user_id)},
        {"$set": {"password": hashed_password}}
    )
    
    return jsonify({"message": "Password changed successfully"}), 200

@app.route('/leaderboard', methods=['GET'])
@jwt_required()
def get_leaderboard():
    subject = request.args.get('subject')
    time_range = request.args.get('time_range', 'all')  # all, weekly, monthly
    
    # Build date range filter
    date_filter = {}
    now = datetime.utcnow()
    
    if time_range == 'weekly':
        start_date = now - timedelta(days=now.weekday())
        start_date = datetime(start_date.year, start_date.month, start_date.day)
        date_filter = {"date": {"$gte": start_date}}
    elif time_range == 'monthly':
        start_date = datetime(now.year, now.month, 1)
        date_filter = {"date": {"$gte": start_date}}
    
    # Build query
    query = {}
    query.update(date_filter)
    
    # Subject filter for quiz lookup
    quiz_filter = {}
    if subject:
        quiz_filter["subject"] = subject
    
    # Get all attempts
    all_attempts = list(attempts.find(query))
    
    # Group attempts by user and calculate average scores
    user_scores = {}
    
    for attempt in all_attempts:
        # If subject filter, check if quiz matches
        if subject:
            try:
                quiz = quizzes.find_one({"_id": attempt["quiz_id"]})
                if not quiz or quiz.get("subject") != subject:
                    continue
            except:
                continue
        
        user_id = str(attempt['user_id'])
        
        if user_id not in user_scores:
            user_scores[user_id] = {
                "total_score": 0,
                "attempts": 0,
                "quizzes": set()
            }
        
        user_scores[user_id]["total_score"] += attempt["score"]
        user_scores[user_id]["attempts"] += 1
        user_scores[user_id]["quizzes"].add(str(attempt["quiz_id"]))
    
    # Calculate average scores and get user details
    leaderboard = []
    
    for user_id, data in user_scores.items():
        avg_score = data["total_score"] / data["attempts"] if data["attempts"] > 0 else 0
        
        try:
            user = users.find_one({"_id": ObjectId(user_id)})
            if user:
                leaderboard.append({
                    "user_id": user_id,
                    "name": user["name"],
                    "avg_score": avg_score,
                    "attempts": data["attempts"],
                    "unique_quizzes": len(data["quizzes"])
                })
        except:
            continue
    
    # Sort leaderboard by average score
    leaderboard.sort(key=lambda x: x["avg_score"], reverse=True)
    
    # Limit to top 20
    leaderboard = leaderboard[:20]
    
    return jsonify({
        "leaderboard": leaderboard,
        "time_range": time_range,
        "subject": subject if subject else "all"
    }), 200

@app.route('/share-quiz/<quiz_id>', methods=['POST'])
@jwt_required()
def share_quiz(quiz_id):
    try:
        quiz = quizzes.find_one({"_id": ObjectId(quiz_id)})
    except:
        return jsonify({"error": "Quiz not found"}), 404
    
    if not quiz:
        return jsonify({"error": "Quiz not found"}), 404
    
    # Check if quiz is already shareable
    if quiz.get("shareable") and quiz.get("share_id"):
        share_links = quiz.get("share_links", {})
        return jsonify({
            "message": "Quiz is already shareable",
            "share_links": share_links
        }), 200
    
    # Generate share ID and links
    share_id = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    share_links = {
        "direct": f"/quiz/{share_id}",
        "whatsapp": f"https://wa.me/?text=Try this quiz: /quiz/{share_id}",
        "twitter": f"https://twitter.com/intent/tweet?text=Try this quiz: /quiz/{share_id}",
        "facebook": f"https://www.facebook.com/sharer/sharer.php?u=/quiz/{share_id}",
        "instagram": f"/quiz/{share_id}"  # For copy-paste as Instagram doesn't have direct sharing
    }
    
    # Update quiz
    quizzes.update_one(
        {"_id": ObjectId(quiz_id)},
        {"$set": {
            "shareable": True,
            "share_id": share_id,
            "share_links": share_links
        }}
    )
    
    return jsonify({
        "message": "Quiz is now shareable",
        "share_links": share_links
    }), 200

@app.route('/analytics/quiz/<quiz_id>', methods=['GET'])
@jwt_required()
def quiz_analytics(quiz_id):
    current_user_id = get_jwt_identity()
    
    try:
        quiz = quizzes.find_one({
            "_id": ObjectId(quiz_id),
            "created_by": ObjectId(current_user_id)
        })
    except:
        return jsonify({"error": "Quiz not found or access denied"}), 404
    
    if not quiz:
        return jsonify({"error": "Quiz not found or access denied"}), 404
    
    # Get all attempts for this quiz
    quiz_attempts = list(attempts.find({"quiz_id": ObjectId(quiz_id)}))
    
    # Basic analytics
    total_attempts = len(quiz_attempts)
    avg_score = sum(attempt["score"] for attempt in quiz_attempts) / total_attempts if total_attempts > 0 else 0
    
    # Question performance
    question_stats = {}
    for q_id in quiz["questions"]:
        correct_count = 0
        attempt_count = 0
        
        for attempt in quiz_attempts:
            if q_id in attempt.get("question_results", {}):
                attempt_count += 1
                if attempt["question_results"][q_id]["is_correct"]:
                    correct_count += 1
        
        success_rate = (correct_count / attempt_count) * 100 if attempt_count > 0 else 0
        
        try:
            question = questions.find_one({"_id": ObjectId(q_id)})
            question_text = question["question_text"] if question else "Unknown question"
        except:
            question_text = "Unknown question"
        
        question_stats[q_id] = {
            "question_text": question_text,
            "success_rate": success_rate,
            "attempt_count": attempt_count
        }
    
    # Time analytics
    time_stats = {
        "avg_time": sum(attempt.get("time_taken_minutes", 0) for attempt in quiz_attempts) / total_attempts if total_attempts > 0 else 0,
        "min_time": min((attempt.get("time_taken_minutes", 0) for attempt in quiz_attempts), default=0),
        "max_time": max((attempt.get("time_taken_minutes", 0) for attempt in quiz_attempts), default=0)
    }
    
    return jsonify({
        "quiz_id": quiz_id,
        "total_attempts": total_attempts,
        "avg_score": avg_score,
        "question_stats": question_stats,
        "time_stats": time_stats
    }), 200

@app.route('/export-progress', methods=['GET'])
@jwt_required()
def export_progress():
    current_user_id = get_jwt_identity()
    format_type = request.args.get('format', 'json')  # json, csv
    
    # Get user
    user = users.find_one({"_id": ObjectId(current_user_id)})
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get user's attempts
    user_attempts = list(attempts.find({"user_id": ObjectId(current_user_id)}))
    
    # Format data
    progress_data = []
    for attempt in user_attempts:
        try:
            quiz = quizzes.find_one({"_id": attempt["quiz_id"]})
            quiz_title = quiz['title'] if quiz else "Unknown Quiz"
            subject = quiz['subject'] if quiz else "Unknown"
            difficulty = quiz['difficulty'] if quiz else "Unknown"
        except:
            quiz_title = "Unknown Quiz"
            subject = "Unknown"
            difficulty = "Unknown"
        
        progress_data.append({
            "date": attempt['date'].strftime('%Y-%m-%d %H:%M:%S'),
            "quiz_title": quiz_title,
            "subject": subject,
            "difficulty": difficulty,
            "score": attempt['score'],
            "correct_count": attempt['correct_count'],
            "total_questions": attempt['total_questions'],
            "time_taken_minutes": attempt.get('time_taken_minutes', 0)
        })
    
    # Return based on format
    if format_type == 'csv':
        csv_data = "Date,Quiz Title,Subject,Difficulty,Score,Correct Count,Total Questions,Time Taken (minutes)\n"
        for item in progress_data:
            csv_data += f"{item['date']},{item['quiz_title']},{item['subject']},{item['difficulty']},{item['score']},{item['correct_count']},{item['total_questions']},{item['time_taken_minutes']}\n"
        
        return csv_data, 200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': f'attachment; filename=edulearn_progress_{user["name"]}_{datetime.utcnow().strftime("%Y%m%d")}.csv'
        }
    else:
        return jsonify({
            "user": user['name'],
            "export_date": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "progress": progress_data
        }), 200

@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Check MongoDB connection
        mongo.db.command('ping')
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "version": "1.0.0"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"error": "Unauthorized"}), 401

if __name__ == '__main__':
    app.run(debug=os.environ.get('DEBUG', 'False') == 'True',
            host=os.environ.get('HOST', '0.0.0.0'),
            port=int(os.environ.get('PORT', 5000)))