"""FastAPI application exposing the Multi-Agentic Security System API."""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

from .service import InputValidationError, ScanService


def create_app(service: Optional[ScanService] = None) -> FastAPI:
    svc = service or ScanService()
    application = FastAPI(
        title="Multi-Agentic Dependency Security API",
        version="0.1.0",
        description="API wrapper over the five-agent dependency verification pipeline.",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @application.exception_handler(InputValidationError)
    async def _validation_handler(request: Request, exc: InputValidationError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    @application.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception):
        return JSONResponse(status_code=500, content={"detail": "An unexpected server error occurred."})

    @application.get("/api/health")
    def get_health():
        return svc.health_info()

    @application.get("/api/scans")
    def list_scans(limit: int = 25):
        return svc.list_scans_and_stats(limit=limit)

    @application.post("/api/scans")
    async def create_scan(
        files: list[UploadFile] = File(default=[]),
        project_name: Optional[str] = Form(default=None),
        text: Optional[str] = Form(default=None),
        git_url: Optional[str] = Form(default=None),
        variant: str = Form(default="R0"),
        registry_mode: str = Form(default="snapshot"),
        evidence_cutoff: Optional[str] = Form(default=None),
        verifier_enabled: bool = Form(default=True),
        wait: bool = Form(default=False),
    ):
        uploaded: list[tuple[str, bytes]] = []
        for f in files:
            if not f.filename:
                continue
            data = await f.read()
            uploaded.append((f.filename, data))
        result = svc.submit_scan(
            project_name=project_name,
            uploaded_files=uploaded or None,
            pasted_text=text,
            git_url=git_url,
            variant=variant,
            registry_mode=registry_mode,
            evidence_cutoff=evidence_cutoff,
            verifier_enabled=verifier_enabled,
            wait=wait,
        )
        return result

    @application.get("/api/scans/{scan_id}")
    def get_scan(scan_id: str):
        detail = svc.get_scan_detail(scan_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return detail

    @application.get("/api/scans/{scan_id}/export")
    def export_scan(scan_id: str):
        detail = svc.get_scan_detail(scan_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        report = svc.export_report(scan_id)
        if report is None:
            raise HTTPException(status_code=409, detail="Report is not available for this scan.")
        import json

        payload = json.dumps(report, indent=2, ensure_ascii=False)
        filename = f"security-report-{scan_id}.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    return application


app = create_app()
