from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Any, Dict

from app.services.streaming import StreamingSessionManager


router = APIRouter()
manager = StreamingSessionManager()


@router.websocket("/stream")
async def mood_stream(websocket: WebSocket) -> None:
    """
    Hybrid real-time stream endpoint.

    Expects JSON messages:
    { "type": "text" | "image" | "audio", "payload": ... }
    """
    await manager.connect(websocket)
    try:
        while True:
            data: Dict[str, Any] = await websocket.receive_json()
            response = await manager.handle_message(websocket, data)
            if response is not None:
                await websocket.send_json(response)
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


