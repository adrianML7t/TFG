import logging
from typing import Optional
from uuid import UUID
import os
import httpx
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, status
from pydantic import BaseModel

# Configuración de Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [Alice1] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Rutas para obtener claves y interconectar con otros módulos (por defecto en localhost)
BDD_A1_FILE_PATH = "BDD_A1.txt"
BOB1_RELAY_REQUEST_URL = os.getenv("BOB1_URL", "http://127.0.0.1:8002/relay_process_request")
MY_RELAY_RESPONSE_URL = os.getenv("ALICE1_RESPONSE_URL", "http://127.0.0.1:8004/relay_process_response")

# Modelos de pydantic
class RelayProcessRequest(BaseModel):
    app_src_id: str
    app_dst_id: str
    k1_id: UUID
    alice1_response_url: str

class FinalNotification(BaseModel):
    k1_id: UUID
    overall_status: str
    message: Optional[str] = None

# Lógica para leer K1_ID de la BDD
def get_first_k1_id_from_bdd(file_path: str) -> Optional[UUID]:
    # Lee la primera línea del archivo BDD y devuelve el key_ID como UUID
    logger.info(f"Alice1: Leyendo K1_ID del archivo: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            first_line = f.readline()
            if not first_line:
                logger.error(f"Alice1: El archivo BDD ('{file_path}') está vacío.")
                return None
            entry = json.loads(first_line)
            k1_id_str = entry.get("key_ID")
            if not k1_id_str:
                logger.error(f"Alice1: La primera entrada en '{file_path}' no contiene 'key_ID'.")
                return None
            return UUID(k1_id_str)
    except FileNotFoundError:
        logger.error(f"Alice1: Archivo BDD ('{file_path}') no encontrado.")
        return None
    except Exception as e:
        logger.error(f"Alice1: Error al leer o procesar K1_ID de '{file_path}': {e}", exc_info=True)
        return None

# Lógica para iniciar el proceso de relay
async def initiate_key_relay_process():
    # Función para que Alice1 inicie el proceso de relay llamando a Bob1
    logger.info("Alice1: Iniciando el proceso de relay de claves...")
    
    # Obtener el K1_ID desde el archivo BDD_A1.txt
    k1_id_to_relay = get_first_k1_id_from_bdd(BDD_A1_FILE_PATH)
    
    if not k1_id_to_relay:
        logger.error("Alice1: No se pudo obtener K1_ID de la BDD. Abortando inicio del proceso.")
        return

    request_payload = RelayProcessRequest(
        app_src_id="Alice1_App_Instance_002",
        app_dst_id="Target_App_ABC",
        k1_id=k1_id_to_relay,
        alice1_response_url=MY_RELAY_RESPONSE_URL
    )

    try:
        payload_json_str = request_payload.model_dump_json()
    except AttributeError:
        payload_json_str = request_payload.json()

    logger.info(f"Alice1: Enviando petición a Bob1 ({BOB1_RELAY_REQUEST_URL}) para K1_ID: {request_payload.k1_id}")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                BOB1_RELAY_REQUEST_URL,
                content=payload_json_str,
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            response.raise_for_status()
            logger.info(f"Alice1: Petición a Bob1 aceptada (Status: {response.status_code}).")
    except Exception as e:
        logger.error(f"Alice1: Error al iniciar el proceso con Bob1: {e}", exc_info=True)

# Configuración del Lifespan para comunicación asíncrona
@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    logger.info("Iniciando Alice1...")
    await initiate_key_relay_process()
    logger.info(f"Alice1: Arranque completo. Escuchando en {MY_RELAY_RESPONSE_URL}")
    yield
    logger.info("Alice1 apagándose...")

app = FastAPI(title="Alice1 - Key Relay Initiator (from BDD)", lifespan=lifespan)

# Endpoint para recibir la notificación final de Bob1
@app.post("/relay_process_response", status_code=status.HTTP_200_OK)
async def receive_final_notification(payload: FinalNotification):
    logger.info(f"Alice1: ¡Notificación final RECIBIDA! Para K1_ID: {payload.k1_id}")
    logger.info(f"  Estado General del Proceso: {payload.overall_status}")
    if payload.message:
        logger.info(f"  Mensaje de Bob1: {payload.message}")
    return {"status": "Notification received by Alice1. Process complete."}

@app.get("/")
async def read_root_alice1():
  return {"message": "Alice1 está activa."}

# Para ejecutar: uvicorn Alice1:app --reload --host 0.0.0.0 --port 8004



