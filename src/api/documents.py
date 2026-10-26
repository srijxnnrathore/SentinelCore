from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from src.schemas.document import DocumentCreate, DocumentResponse
from src.api.deps import get_tenant_db, get_auth_context, AuthContext
from src.core.audit import log_security_event
from src.core.threat_detector import threat_detector

router = APIRouter(prefix="/documents", tags=["Documents"])

@router.post("/", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_document(
    payload: DocumentCreate,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_tenant_db),
):
    query = text("""
        INSERT INTO documents (tenant_id, title, content)
        VALUES (:tenant_id, :title, :content)
        RETURNING id, tenant_id, title, content, created_at
    """)
    result = await db.execute(
        query,
        {
            "tenant_id": str(auth.tenant_id),
            "title": payload.title,
            "content": payload.content,
        }
    )
    row = result.mappings().one()

    client_ip = request.client.host if request.client else None
    await log_security_event(
        actor_id=auth.actor_id,
        action="DOCUMENT_CREATE",
        status="SUCCESS",
        tenant_id=auth.tenant_id,
        resource_id=str(row["id"]),
        ip_address=client_ip,
    )

    return row

@router.get("/", response_model=List[DocumentResponse])
async def list_documents(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_tenant_db),
):
    query = text("""
        SELECT id, tenant_id, title, content, created_at
        FROM documents
        ORDER BY created_at DESC
    """)
    result = await db.execute(query)
    rows = result.mappings().all()

    client_ip = request.client.host if request.client else None
    await log_security_event(
        actor_id=auth.actor_id,
        action="DOCUMENT_LIST",
        status="SUCCESS",
        tenant_id=auth.tenant_id,
        ip_address=client_ip,
    )

    return rows

@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_tenant_db),
):
    query = text("""
        SELECT id, tenant_id, title, content, created_at
        FROM documents
        WHERE id = :doc_id
    """)
    result = await db.execute(query, {"doc_id": str(document_id)})
    row = result.mappings().one_or_none()

    client_ip = request.client.host if request.client else None

    if row is None:
        # 1. Log forensic denied event
        await log_security_event(
            actor_id=auth.actor_id,
            action="DOCUMENT_READ_DENIED",
            status="DENIED",
            tenant_id=auth.tenant_id,
            resource_id=str(document_id),
            ip_address=client_ip,
        )

        # 2. Feed security event into the automated threat detector
        await threat_detector.record_violation(str(auth.tenant_id))

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )

    await log_security_event(
        actor_id=auth.actor_id,
        action="DOCUMENT_READ",
        status="SUCCESS",
        tenant_id=auth.tenant_id,
        resource_id=str(document_id),
        ip_address=client_ip,
    )

    return row