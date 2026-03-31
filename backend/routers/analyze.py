# ---------------------------------------------------------------------------
# routers/analyze.py
# Orchestrates the full log analysis pipeline for a given upload.
#
# POST /api/analyze/{upload_id} -> parses the log, calls Claude, saves result
# GET  /api/results/{upload_id} -> fetches a previously saved analysis result
# ---------------------------------------------------------------------------

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database import get_db
from models import Upload, AnalysisResult
from routers.auth import get_current_user
from parser import parse_log_file, get_summary_stats
from ai import analyze_logs
import json

router = APIRouter()


@router.post("/analyze/{upload_id}")
async def analyze(
    upload_id: str,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Runs the full analysis pipeline on a previously uploaded log file.

    Pipeline steps:
        1. Authenticate the user via JWT.
        2. Look up the Upload record and confirm it belongs to this user.
        3. If already analyzed ("done"), return the cached result immediately.
        4. Mark the upload as "analyzing" to prevent duplicate runs.
        5. Parse the log file into structured events.
        6. Compute summary statistics across all events.
        7. Send events + stats to Claude for AI analysis.
        8. Save the AI result to the database and mark the upload as "done".

    On any error, the upload status is set to "error" before re-raising.

    Args:
        upload_id:     UUID of the Upload record to analyze.
        authorization: "Bearer <token>" header from the frontend.
        db:            Active database session (injected by FastAPI).
    """
    # Validate the token and identify the requesting user
    token = authorization.replace("Bearer ", "")
    current_user = get_current_user(token, db)

    # Look up the upload — also verify it belongs to the current user
    upload = db.query(Upload).filter(
        Upload.id == upload_id,
        Upload.user_id == current_user.id
    ).first()

    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    # If this upload was already analyzed, return the cached result
    if upload.status == "done":
        result = db.query(AnalysisResult).filter(
            AnalysisResult.upload_id == upload.id
        ).first()
        return format_result(result)

    # Mark the upload as in-progress so the frontend can show a loading state
    upload.status = "analyzing"
    db.commit()

    try:
        # Step 1 — Parse the raw log file into a list of event dicts
        events = parse_log_file(upload.file_path)

        if not events:
            raise HTTPException(status_code=400, detail="No valid log events found in file")

        # Step 2 — Compute aggregate stats (totals, user counts, risky countries, etc.)
        stats = get_summary_stats(events)

        # Step 3 — Send the events and stats to Claude for AI-powered analysis
        ai_result = analyze_logs(events, stats)

        # Step 4 — Persist the AI result to the database
        result = AnalysisResult(
            upload_id=upload.id,
            summary=ai_result.get("summary", ""),
            timeline=ai_result.get("timeline", []),
            anomalies=ai_result.get("anomalies", []),
            top_users=ai_result.get("top_users", []),
            threat_breakdown=ai_result.get("threat_breakdown", {})
        )
        db.add(result)

        # Mark the upload as complete
        upload.status = "done"
        db.commit()
        db.refresh(result)

        return format_result(result)

    except Exception as e:
        # If anything goes wrong, record the failure and surface the error
        upload.status = "error"
        db.commit()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{upload_id}")
def get_results(
    upload_id: str,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Fetches the saved analysis result for a completed upload.

    Returns HTTP 404 if:
        - The upload doesn't exist or doesn't belong to this user.
        - The analysis has not been run yet (no result record exists).

    Args:
        upload_id:     UUID of the Upload to retrieve results for.
        authorization: "Bearer <token>" header from the frontend.
        db:            Active database session (injected by FastAPI).
    """
    # Validate the token and identify the requesting user
    token = authorization.replace("Bearer ", "")
    current_user = get_current_user(token, db)

    # Confirm the upload exists and belongs to this user
    upload = db.query(Upload).filter(
        Upload.id == upload_id,
        Upload.user_id == current_user.id
    ).first()

    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    # Fetch the associated analysis result
    result = db.query(AnalysisResult).filter(
        AnalysisResult.upload_id == upload.id
    ).first()

    if not result:
        raise HTTPException(status_code=404, detail="No results yet")

    return format_result(result)


def format_result(result: AnalysisResult) -> dict:
    """
    Converts an AnalysisResult ORM object into a plain dict for the API response.

    Keeps the response shape consistent regardless of which endpoint returns it.
    """
    return {
        "summary": result.summary,
        "timeline": result.timeline,
        "anomalies": result.anomalies,
        "top_users": result.top_users,
        "threat_breakdown": result.threat_breakdown,
        "created_at": str(result.created_at)
    }
