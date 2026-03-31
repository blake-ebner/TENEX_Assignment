# ---------------------------------------------------------------------------
# routers/upload.py
# Handles file uploads and listing a user's upload history.
#
# POST /api/upload  -> accepts a .log or .txt file, saves it to disk,
#                      and creates an Upload record in the database
# GET  /api/uploads -> returns all uploads belonging to the current user
# ---------------------------------------------------------------------------

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Header
from sqlalchemy.orm import Session
from database import get_db
from models import Upload
from routers.auth import get_current_user
import os
import shutil
import uuid

router = APIRouter()

# Directory where uploaded files are stored on disk
UPLOAD_DIR = "uploads"

# Create the uploads directory if it doesn't already exist
os.makedirs(UPLOAD_DIR, exist_ok=True)


@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Accepts a log file upload from an authenticated user.

    Steps:
        1. Validate the JWT token from the Authorization header.
        2. Reject any file that isn't a .log or .txt.
        3. Save the file to disk with a UUID-prefixed name to avoid collisions.
        4. Create an Upload record in the database with status "pending".
        5. Return the upload ID, filename, and status.

    Args:
        file:          The uploaded file (multipart/form-data).
        authorization: "Bearer <token>" header from the frontend.
        db:            Active database session (injected by FastAPI).
    """
    # Strip the "Bearer " prefix and validate the token
    token = authorization.replace("Bearer ", "")
    current_user = get_current_user(token, db)

    # Only allow .log and .txt files to prevent uploading arbitrary content
    if not file.filename.endswith((".log", ".txt")):
        raise HTTPException(status_code=400, detail="Only .log and .txt files are allowed")

    # Generate a unique filename to prevent overwriting existing files
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{file.filename}")

    # Write the uploaded file to disk
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Save the upload metadata to the database
    upload = Upload(
        user_id=current_user.id,
        filename=file.filename,
        file_path=file_path,
        status="pending"           # Will be updated to "analyzing" then "done"
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)

    return {
        "upload_id": str(upload.id),
        "filename": upload.filename,
        "status": upload.status
    }


@router.get("/uploads")
def get_uploads(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Returns all uploads that belong to the currently authenticated user.

    Each item in the response includes the upload ID, filename, current
    status, and the time it was uploaded.

    Args:
        authorization: "Bearer <token>" header from the frontend.
        db:            Active database session (injected by FastAPI).
    """
    # Validate the token and identify the requesting user
    token = authorization.replace("Bearer ", "")
    current_user = get_current_user(token, db)

    # Fetch all uploads owned by this user
    uploads = db.query(Upload).filter(Upload.user_id == current_user.id).all()

    # Return a clean list of dicts (avoid exposing internal file paths)
    return [
        {
            "upload_id": str(u.id),
            "filename": u.filename,
            "status": u.status,
            "uploaded_at": str(u.uploaded_at)
        }
        for u in uploads
    ]
