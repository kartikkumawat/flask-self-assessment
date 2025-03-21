# EduLearn API Documentation

## Overview
The EduLearn API provides a platform for users to register, login, create quizzes, attempt quizzes, and track their progress. This documentation outlines the available endpoints, required fields, methods, and their uses.

## Base URL
```
http://<your-domain-or-ip>:<port>
```

## Authentication
All endpoints except for registration, email verification, and password reset require a JWT token for authentication. The token should be included in the `Authorization` header as follows:
```
Authorization: Bearer <your_token>
```

## Endpoints

### 1. User Registration
- **Endpoint:** `/register`
- **Method:** `POST`
- **Description:** Registers a new user.
- **Required Fields:**
  - `name`: User's full name.
  - `email`: User's email address.
  - `password`: User's password.
  - `location`: User's location.
  - `dob`: User's date of birth (YYYY-MM-DD).
  - `roll_number`: User's roll number.

### 2. Email Verification
- **Endpoint:** `/verify-email/<token>`
- **Method:** `GET`
- **Description:** Verifies the user's email address using a token.
- **Required Fields:** None (token is passed in the URL).

### 3. User Login
- **Endpoint:** `/login`
- **Method:** `POST`
- **Description:** Authenticates a user and returns a JWT token.
- **Required Fields:**
  - `email`: User's email address.
  - `password`: User's password.

### 4. Get User Profile
- **Endpoint:** `/profile`
- **Method:** `GET`
- **Description:** Retrieves the authenticated user's profile.
- **Required Fields:** None.

### 5. Update User Profile
- **Endpoint:** `/profile`
- **Method:** `PUT`
- **Description:** Updates the authenticated user's profile.
- **Required Fields:**
  - `name`: User's full name (optional).
  - `location`: User's location (optional).
  - `dob`: User's date of birth (optional).
  - `preferences`: User's preferences (optional).

### 6. Add Question
- **Endpoint:** `/questions`
- **Method:** `POST`
- **Description:** Adds a new question to the database.
- **Required Fields:**
  - `subject`: Subject of the question.
  - `question_text`: The question text.
  - `options`: List of answer options (at least 2).
  - `correct_answer`: The correct answer from the options.
  - `difficulty`: Difficulty level (easy, medium, hard).

### 7. Get Questions
- **Endpoint:** `/questions`
- **Method:** `GET`
- **Description:** Retrieves questions based on optional filters.
- **Optional Query Parameters:**
  - `subject`: Filter by subject.
  - `difficulty`: Filter by difficulty.

### 8. Generate Quiz
- **Endpoint:** `/generate-quiz`
- **Method:** `POST`
- **Description:** Generates a quiz based on specified criteria.
- **Required Fields:**
  - `subject`: Subject of the quiz.
  - `difficulty`: Difficulty level (easy, medium, hard, mixed).
  - `question_count`: Number of questions in the quiz.
  - `time_limit`: Time limit for the quiz in minutes.

### 9. Get Quiz
- **Endpoint:** `/quiz/<quiz_id>`
- **Method:** `GET`
- **Description:** Retrieves a quiz by its ID or share ID.
- **Required Fields:** None (quiz ID is passed in the URL).

### 10. Attempt Quiz
- **Endpoint:** `/attempt-quiz`
- **Method:** `POST`
- **Description:** Submits answers for a quiz attempt.
- **Required Fields:**
  - `quiz_id`: ID of the quiz being attempted.
  - `answers`: Dictionary of question IDs and user answers.

### 11. Get Progress
- **Endpoint:** `/progress`
- **Method:** `GET`
- **Description:** Retrieves the user's quiz attempt progress.
- **Optional Query Parameters:**
  - `filter`: Filter type (all, daily, weekly, monthly, yearly).
  - `subject`: Filter by subject.
  - `difficulty`: Filter by difficulty.

### 12. Schedule Quiz
- **Endpoint:** `/scheduled-quizzes`
- **Method:** `POST`
- **Description:** Schedules a quiz for the user.
- **Required Fields:**
  - `frequency`: Frequency of the quiz (daily, weekly, monthly).
  - `subject`: Subject of the quiz.
  - `difficulty`: Difficulty level.
  - `question_count`: Number of questions.
  - `time_limit`: Time limit for the quiz in minutes.

### 13. Resend Verification Email
- **Endpoint:** `/resend-verification`
- **Method:** `POST`
- **Description:** Resends the email verification link to the user.
- **Required Fields:**
  - `email`: User's email address.

### 14. Forgot Password
- **Endpoint:** `/forgot-password`
- **Method:** `POST`
- **Description:** Initiates the password reset process.
- **Required Fields:**
  - `email`: User's email address.

### 15. Reset Password
- **Endpoint:** `/reset-password/<token>`
- **Method:** `POST`
- **Description:** Resets the user's password using a token.
- **Required Fields:**
  - `password`: New password.

### 16. Get User Quizzes
- **Endpoint:** `/quizzes`
- **Method:** `GET`
- **Description:** Retrieves quizzes created by the authenticated user.
- **Required Fields:** None.

### 17. Get Attempt Details
- **Endpoint:** `/attempt/<attempt_id>`
- **Method:** `GET`
- **Description:** Retrieves details of a specific quiz attempt.
- **Required Fields:** None (attempt ID is passed in the URL).

### 18. Change Password
- **Endpoint:** `/change-password`
- **Method:** `POST`
- **Description:** Changes the user's password.
- **Required Fields:**
  - `current_password`: User's current password.
  - `new_password`: User's new password.

### 19. Get Leaderboard
- **Endpoint:** `/leaderboard`
- **Method:** `GET`
- **Description:** Retrieves the leaderboard based on quiz attempts.
- **Optional Query Parameters:**
  - `subject`: Filter by subject.
  - `time_range`: Time range for filtering (all, weekly, monthly).

### 20. Share Quiz
- **Endpoint:** `/share-quiz/<quiz_id>`
- **Method:** `POST`
- **Description:** Makes a quiz shareable and generates share links.
- **Required Fields:** None (quiz ID is passed in the URL).

### 21. Quiz Analytics
- **Endpoint:** `/analytics/quiz/<quiz_id>`
- **Method:** `GET`
- **Description:** Retrieves analytics for a specific quiz.
- **Required Fields:** None (quiz ID is passed in the URL).

### 22. Export Progress
- **Endpoint:** `/export-progress`
- **Method:** `GET`
- **Description:** Exports the user's progress in JSON or CSV format.
- **Optional Query Parameters:**
  - `format`: Format of the export (json, csv).

### 23. Health Check
- **Endpoint:** `/health`
- **Method:** `GET`
- **Description:** Checks the health of the API and database connection.
- **Required Fields:** None.

## Error Handling
The API returns standard HTTP status codes along with JSON error messages for various scenarios:
- **404 Not Found:** Resource not found.
- **500 Internal Server Error:** Server encountered an error.
- **400 Bad Request:** Invalid request format or missing fields.
- **401 Unauthorized:** Authentication failed.

## Conclusion
This documentation provides a comprehensive overview of the EduLearn API, including endpoints, required fields, and their respective functionalities. For any further questions or issues, please refer to the support team.
