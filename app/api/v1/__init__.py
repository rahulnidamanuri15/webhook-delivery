from fastapi import APIRouter

from app.api.v1.events import router as events_router

api_router = APIRouter()
api_router.include_router(events_router)
