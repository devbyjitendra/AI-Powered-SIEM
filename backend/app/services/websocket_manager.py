from fastapi import WebSocket
from typing import List, Set
import asyncio
from app.core.logging import logger

class WebSocketManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.main_loop: asyncio.AbstractEventLoop = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        self.main_loop = asyncio.get_running_loop()
        logger.info(f"New WebSocket client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        
        logger.info(f"Broadcasting message via WebSocket to {len(self.active_connections)} clients.")
        disconnected_clients = set()
        
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending message to WebSocket client: {e}")
                disconnected_clients.add(connection)
                
        for client in disconnected_clients:
            self.disconnect(client)

    def broadcast_threadsafe(self, message: dict):
        """
        Broadcasts message to WebSocket clients from any thread safely by scheduling
        it on the main event loop.
        """
        logger.info(f"[WS_BROADCAST] broadcast_threadsafe called. Connections: {len(self.active_connections)} | Main loop: {self.main_loop}")
        if not self.active_connections:
            logger.info("[WS_BROADCAST] No active connections. Skipping.")
            return
            
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        if current_loop and current_loop == self.main_loop:
            current_loop.create_task(self.broadcast(message))
        elif self.main_loop and self.main_loop.is_running():
            asyncio.run_coroutine_threadsafe(self.broadcast(message), self.main_loop)
        else:
            # Fallback if loop is not running or not captured yet
            if current_loop:
                current_loop.create_task(self.broadcast(message))
            else:
                try:
                    asyncio.run(self.broadcast(message))
                except Exception as e:
                    logger.error(f"Failed to run broadcast in fallback event loop: {e}")

manager = WebSocketManager()

