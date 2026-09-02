# ---------------------------------------------------------------------------
# routers/analyze.py
# Orchestrates the full log analysis pipeline for a given upload.
#
# Analysis takes 15-20 seconds, so it runs as a background job rather than
# holding an HTTP request open. The frontend starts the job, polls for the
# current stage, then fetches the finished report.
#
# POST /api/analyze/{upload_id}        -> starts (or resumes) the analysis
# GET  /api/analyze/{upload_id}/status -> current status and pipeline stage
# GET  /api/results/{upload_id}        -> the saved analysis result
# ---------------------------------------------------------------------------

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Header
from sqlalchemy.orm import Session
from database import get_db, SessionLocal
from models import Upload, AnalysisResult
from routers.auth import get_current_user
from parser import parse_log_file, get_summary_stats, select_significant_events
from trends import build_trends
from ai import analyze_logs, MAX_EVENTS_IN_PROMPT

router = APIRouter()

# Upload IDs currently being analyzed by this process.
#
# The database status alone cannot distinguish "running right now" from
# "was running when the server was killed" — without this, a crash would leave
# an upload stuck on "analyzing" forever with no way to retry it.
_in_flight: set[str] = set()

# Statuses that mean the pipeline has not finished successfully
RETRYABLE = {"pending", "error"}


def _get_owned_upload(upload_id: str, authorization: str, db: Session) -> Upload:
    """
    Validates the JWT and returns the Upload, if it belongs to that user.

    Raises HTTP 401 for a bad token and HTTP 404 if the upload does not exist
    or belongs to someone else — the same response either way, so this cannot
    be used to probe which upload IDs exist.
    """
    token = authorization.replace("Bearer ", "")
    current_user = get_current_user(token, db)

    upload = db.query(Upload).filter(
        Upload.id == upload_id,
        Upload.user_id == current_user.id
    ).first()

    if not upload:
        raise HTTPException(status_code=404, detail="Upload not found")

    return upload


def _set_stage(db: Session, upload: Upload, stage: str) -> None:
    """Records which pipeline step is running so the frontend can display it."""
    upload.stage = stage
    db.commit()


async def run_analysis(upload_id: str) -> None:
    """
    The background job: parses the log, calls Claude, and saves the result.

    Runs after the HTTP response has been sent, on its own database session
    (the request's session is already closed by then). Progress is written to
    the Upload row as it goes; failures are recorded there rather than raised,
    since there is no longer a request to return an error to.

    Args:
        upload_id: UUID of the Upload record to analyze.
    """
    _in_flight.add(upload_id)
    db = SessionLocal()

    try:
        upload = db.query(Upload).filter(Upload.id == upload_id).first()
        if not upload:
            return

        upload.status = "analyzing"
        upload.error_message = None
        _set_stage(db, upload, "Reading log file")

        # Step 1 — Parse the raw log file into a list of event dicts
        events = parse_log_file(upload.file_path)
        if not events:
            raise ValueError("No valid log events found in file")

        # Step 2 — Compute aggregate stats across every event in the file
        _set_stage(db, upload, f"Parsed {len(events)} events")
        stats = get_summary_stats(events)

        # Step 3 — Pick which events are worth the prompt's token budget.
        # For a small file this is all of them; for a large one it is the most
        # significant events plus a sample of routine traffic.
        selected = select_significant_events(events, MAX_EVENTS_IN_PROMPT)
        if len(selected) < len(events):
            _set_stage(db, upload, f"Selected {len(selected)} of {len(events)} events")

        # Step 4 — Send to Claude. This is the slow part, 15-20 seconds.
        _set_stage(db, upload, "Claude is analysing the traffic")
        ai_result = await analyze_logs(selected, stats)

        # Step 5 — Persist the report, replacing any result from a previous run
        _set_stage(db, upload, "Saving report")
        db.query(AnalysisResult).filter(
            AnalysisResult.upload_id == upload.id
        ).delete(synchronize_session=False)

        db.add(AnalysisResult(
            upload_id=upload.id,
            summary=ai_result["summary"],
            risk_level=ai_result["risk_level"],
            timeline=ai_result["timeline"],
            anomalies=ai_result["anomalies"],
            top_users=ai_result["top_users"],
            threat_breakdown=ai_result["threat_breakdown"],
            recommendations=ai_result["recommendations"],
            detections=ai_result["detections"],
        ))

        upload.status = "done"
        upload.stage = "Complete"
        db.commit()

    except Exception as e:
        # Record the failure on the upload so the frontend can show it and the
        # user can retry. Re-raising here would only reach the server log.
        db.rollback()
        upload = db.query(Upload).filter(Upload.id == upload_id).first()
        if upload:
            upload.status = "error"
            upload.stage = None
            upload.error_message = str(e)
            db.commit()

    finally:
        db.close()
        _in_flight.discard(upload_id)


@router.post("/analyze/{upload_id}")
def start_analysis(
    upload_id: str,
    background_tasks: BackgroundTasks,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Starts analysis of a previously uploaded log file.

    Returns immediately — poll /api/analyze/{upload_id}/status for progress,
    then GET /api/results/{upload_id} once the status is "done".

    Calling this on an upload that is already finished, or already being
    analyzed by this process, reports the current state instead of starting a
    second run. An upload left mid-analysis by a server restart is retried.

    Args:
        upload_id:     UUID of the Upload record to analyze.
        authorization: "Bearer <token>" header from the frontend.
    """
    upload = _get_owned_upload(upload_id, authorization, db)

    # Already analyzed — nothing to do
    if upload.status == "done":
        return {"status": "done", "stage": "Complete"}

    # Genuinely running right now — report progress rather than duplicating work
    if upload.status not in RETRYABLE and upload_id in _in_flight:
        return {"status": upload.status, "stage": upload.stage}

    upload.status = "queued"
    upload.stage = "Queued"
    upload.error_message = None
    db.commit()

    background_tasks.add_task(run_analysis, upload_id)

    return {"status": "queued", "stage": "Queued"}


@router.get("/analyze/{upload_id}/status")
def get_status(
    upload_id: str,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Reports where an upload is in the analysis pipeline.

    Returns status ("pending", "queued", "analyzing", "done" or "error"), a
    human-readable stage description, and an error message if the run failed.

    Args:
        upload_id:     UUID of the Upload to check.
        authorization: "Bearer <token>" header from the frontend.
    """
    upload = _get_owned_upload(upload_id, authorization, db)

    return {
        "status": upload.status,
        "stage": upload.stage,
        "error": upload.error_message,
    }


@router.get("/results/{upload_id}")
def get_results(
    upload_id: str,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Fetches the saved analysis result for a completed upload.

    Returns HTTP 404 if the upload doesn't belong to this user, and HTTP 409
    if the analysis hasn't finished yet.

    Args:
        upload_id:     UUID of the Upload to retrieve results for.
        authorization: "Bearer <token>" header from the frontend.
    """
    upload = _get_owned_upload(upload_id, authorization, db)

    result = db.query(AnalysisResult).filter(
        AnalysisResult.upload_id == upload.id
    ).first()

    if not result:
        # Distinguish "not finished" from "no such upload" — the frontend polls
        # on the former and gives up on the latter.
        raise HTTPException(
            status_code=409,
            detail=upload.error_message or f"Analysis is not finished (status: {upload.status})",
        )

    return format_result(result, upload)


@router.get("/trends")
def get_trends(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Cross-upload patterns across everything this user has analyzed.

    A per-file report can only describe its own file. This rolls every completed
    report together so repeat offenders and persistent ATT&CK techniques become
    visible — the same user flagged week after week is a different problem from
    one bad afternoon.

    Args:
        authorization: "Bearer <token>" header from the frontend.
    """
    token = authorization.replace("Bearer ", "")
    current_user = get_current_user(token, db)

    # Oldest first so "first seen" and "last seen" come out the right way round
    rows = (
        db.query(AnalysisResult, Upload)
        .join(Upload, AnalysisResult.upload_id == Upload.id)
        .filter(Upload.user_id == current_user.id)
        .order_by(AnalysisResult.created_at.asc())
        .all()
    )

    return build_trends([
        {
            "upload_id": str(upload.id),
            "filename": upload.filename,
            "created_at": str(result.created_at),
            "risk_level": result.risk_level or "Low",
            "anomalies": result.anomalies or [],
        }
        for result, upload in rows
    ])


def format_result(result: AnalysisResult, upload: Upload) -> dict:
    """
    Converts an AnalysisResult ORM object into a plain dict for the API response.

    Keeps the response shape consistent regardless of which endpoint returns it.
    Empty JSONB columns are normalised to empty lists/dicts so the frontend
    never has to guard against null.
    """
    return {
        "filename": upload.filename,
        "summary": result.summary,
        "risk_level": result.risk_level or "Low",
        "timeline": result.timeline or [],
        "anomalies": result.anomalies or [],
        "top_users": result.top_users or [],
        "threat_breakdown": result.threat_breakdown or {},
        "recommendations": result.recommendations or [],
        "detections": result.detections or [],
        "created_at": str(result.created_at),
    }
