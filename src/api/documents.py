import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.deps import AuthContext, get_auth_context, get_db
from src.core.event_queue import SecurityEvent, security_event_queue
from src.schemas.document import DocumentCreate, DocumentResponse

router = APIRouter()

@router.post("/", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_document(
    doc_in: DocumentCreate,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text("""
            INSERT INTO documents (tenant_id, title, content)
            VALUES (:tenant_id, :title, :content)
            RETURNING id, tenant_id, title, content, created_at
        """),
        {
            "tenant_id": auth.tenant_id,
            "title": doc_in.title,
            "content": doc_in.content,
        },
    )
    doc = result.mappings().one()

    security_event_queue.push(
        SecurityEvent(
            tenant_id=auth.tenant_id,
            actor_id=auth.actor_id,
            action="DOCUMENT_CREATE",
            status="SUCCESS",
            resource_id=str(doc["id"]),
            ip_address=request.client.host if request.client else "127.0.0.1",
            record_threat=False,
        )
    )
    return doc

@router.get("/", response_model=List[DocumentResponse])
async def list_documents(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text("SELECT id, tenant_id, title, content, created_at FROM documents")
    )
    docs = result.mappings().all()

    security_event_queue.push(
        SecurityEvent(
            tenant_id=auth.tenant_id,
            actor_id=auth.actor_id,
            action="DOCUMENT_LIST",
            status="SUCCESS",
            resource_id=None,
            ip_address=request.client.host if request.client else "127.0.0.1",
            record_threat=False,
        )
    )
    return docs

@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: uuid.UUID,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text("SELECT id, tenant_id, title, content, created_at FROM documents WHERE id = :id"),
        {"id": document_id},
    )
    doc = result.mappings().one_or_none()

    if not doc:
        probe_result = await db.execute(
            text("SELECT public.check_cross_tenant_probe(:id)"),
            {"id": document_id},
        )
        is_cross_tenant = bool(probe_result.scalar())

        if is_cross_tenant:
            action = "DOCUMENT_READ_DENIED"
            event_status = "DENIED"
            record_threat = True
        else:
            action = "DOCUMENT_NOT_FOUND"
            event_status = "NOT_FOUND"
            record_threat = False

        security_event_queue.push(
            SecurityEvent(
                tenant_id=auth.tenant_id,
                actor_id=auth.actor_id,
                action=action,
                status=event_status,
                resource_id=str(document_id),
                ip_address=request.client.host if request.client else "127.0.0.1",
                record_threat=record_threat,
            )
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    security_event_queue.push(
        SecurityEvent(
            tenant_id=auth.tenant_id,
            actor_id=auth.actor_id,
            action="DOCUMENT_READ",
            status="SUCCESS",
            resource_id=str(doc["id"]),
            ip_address=request.client.host if request.client else "127.0.0.1",
            record_threat=False,
        )
    )
    return doc
