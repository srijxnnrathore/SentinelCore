import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from src.api.deps import AuthContext, get_auth_context, get_db
from src.core.audit import log_security_event
from src.core.threat_detector import threat_detector

router = APIRouter()

class DocumentCreate(BaseModel):
    title: str
    content: str

class DocumentResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    content: str

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
            RETURNING id, tenant_id, title, content
        """),
        {
            "tenant_id": auth.tenant_id,
            "title": doc_in.title,
            "content": doc_in.content,
        },
    )
    doc = result.mappings().one()

    await log_security_event(
        actor_id=auth.actor_id,
        action="DOCUMENT_CREATE",
        status="SUCCESS",
        resource_id=str(doc["id"]),
        ip_address=request.client.host if request.client else "127.0.0.1",
        tenant_id=auth.tenant_id,
    )
    return doc

@router.get("/", response_model=List[DocumentResponse])
async def list_documents(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text("SELECT id, tenant_id, title, content FROM documents")
    )
    docs = result.mappings().all()

    await log_security_event(
        actor_id=auth.actor_id,
        action="DOCUMENT_LIST",
        status="SUCCESS",
        resource_id=None,
        ip_address=request.client.host if request.client else "127.0.0.1",
        tenant_id=auth.tenant_id,
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
        text("SELECT id, tenant_id, title, content FROM documents WHERE id = :id"),
        {"id": document_id},
    )
    doc = result.mappings().one_or_none()

    if not doc:
        probe_result = await db.execute(
            text("SELECT public.check_cross_tenant_probe(:id)"),
            {"id": document_id},
        )
        is_cross_tenant = probe_result.scalar() or False

        # Threat tracking: record violation on missing or cross-tenant probes
        await threat_detector.record_violation(auth.tenant_id)
        action = "DOCUMENT_READ_DENIED" if is_cross_tenant else "DOCUMENT_NOT_FOUND"

        await log_security_event(
            actor_id=auth.actor_id,
            action=action,
            status="DENIED" if is_cross_tenant else "NOT_FOUND",
            resource_id=str(document_id),
            ip_address=request.client.host if request.client else "127.0.0.1",
            tenant_id=auth.tenant_id,
        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    await log_security_event(
        actor_id=auth.actor_id,
        action="DOCUMENT_READ",
        status="SUCCESS",
        resource_id=str(doc["id"]),
        ip_address=request.client.host if request.client else "127.0.0.1",
        tenant_id=auth.tenant_id,
    )
    return doc