from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.training import (
    add_training_example,
    list_training_examples,
    delete_training_example,
    verify_admin_password,
)


router = APIRouter()


class TrainExampleIn(BaseModel):
    admin_password: Optional[str] = Field(default=None)
    user_text: str = Field(..., min_length=1)
    preferred_response: str = Field(..., min_length=1)
    mood_label: Optional[str] = None
    tags: Optional[List[str]] = None


class TrainExampleOut(BaseModel):
    id: str
    user_text: str
    preferred_response: str
    mood_label: Optional[str] = None
    tags: List[str] = []


def _ensure_admin(admin_password: Optional[str]) -> None:
    if not verify_admin_password(admin_password):
        raise HTTPException(status_code=403, detail="Invalid admin password.")


@router.post("/add", response_model=TrainExampleOut)
async def add_example(payload: TrainExampleIn) -> TrainExampleOut:
    """
    Add a curated training example.
    """
    _ensure_admin(payload.admin_password)
    ex = add_training_example(
        user_text=payload.user_text,
        preferred_response=payload.preferred_response,
        mood_label=payload.mood_label,
        tags=payload.tags,
    )
    return TrainExampleOut(**ex)


@router.get("/examples", response_model=List[TrainExampleOut])
async def get_examples(admin_password: Optional[str] = Query(default=None)) -> List[TrainExampleOut]:
    """
    List all training examples (admin only).
    """
    _ensure_admin(admin_password)
    examples = list_training_examples()
    return [TrainExampleOut(**ex) for ex in examples]


@router.delete("/examples/{example_id}")
async def delete_example(example_id: str, admin_password: Optional[str] = Query(default=None)) -> dict:
    """
    Delete a training example by id (admin only).
    """
    _ensure_admin(admin_password)
    deleted = delete_training_example(example_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Example not found.")
    return {"status": "deleted", "id": example_id}


@router.post("/apply")
async def apply_training(admin_password: Optional[str] = None) -> dict:
    """
    Dummy apply endpoint for future use.

    For now, this simply validates admin access and returns OK.
    """
    _ensure_admin(admin_password)
    return {"status": "ok"}


