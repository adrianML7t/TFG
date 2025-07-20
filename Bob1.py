import logging
from typing import List, Optional, Dict, Any
from uuid import UUID
import os
import httpx
import base64
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, status, HTTPException, BackgroundTasks
from pydantic import BaseModel
from enum import Enum

logging.basicConfig(level=logging.INFO, format='%(asctime)s [Bob1] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

ALICE2_EXT_KEYS_URL = os.getenv("ALICE2_URL", "http://127.0.0.1:8000/ext_keys")
MY_ACK_URL_FOR_ALICE2 = os.getenv("BOB1_ACK_URL", "http://127.0.0.1:8002/ack")
BDD_B1_FILE_PATH = "BDD_B1.txt"

alice1_pending_notifications: Dict[str, str] = {}

class RelayRequestFromAlice1(BaseModel):
    app_src_id: str
    app_dst_id: str
    k1_id: UUID
    alice1_response_url: str

class ExtKey_KeyItem(BaseModel):
    key_id: UUID
    value: str
class ExtKeyData(BaseModel):
    keys: List[ExtKey_KeyItem]
    initiator_sae_id: str
    target_sae_ids: List[str]
    ack_callback_url: str
class ExtKeyContainerPayload(BaseModel):
    ext_key_container: ExtKeyData

class AckStatusEnum(str, Enum):
    RELAYED = "relayed"
    VOIDED = "voided"
    FAILED = "failed"
    KEY_NOT_PRESENT = "key not present"
    K1_PROCESSING_ERROR = "k1_processing_error"
    K2_FETCH_ERROR = "k2_fetch_error"
    KCYPHER_GENERATION_ERROR = "kcypher_generation_error"
    BOB2_SEND_ERROR = "bob2_send_error"

class Ack_KeyIdItem(BaseModel):
    key_id: UUID
class AckData(BaseModel):
    key_ids: List[Ack_KeyIdItem]
    ack_status: AckStatusEnum
    initiator_sae_id: str
    target_sae_id: str
    message: Optional[str] = None
class AckContainerPayload(BaseModel):
    ack_container: AckData

class FinalNotificationToAlice1(BaseModel):
    k1_id: UUID
    overall_status: str
    message: Optional[str] = None

def get_k1_value_from_bdd(file_path: str, target_k1_id: UUID) -> Optional[str]:
    logger.info(f"Bob1: Buscando K1_value en '{file_path}' para K1_ID: {target_k1_id}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                entry = json.loads(line)
                if UUID(entry.get("key_ID")) == target_k1_id:
                    k1_value_base64 = entry.get("key")
                    logger.info(f"Bob1: K1_value encontrado para K1_ID {target_k1_id}.")
                    return k1_value_base64
            logger.warning(f"Bob1: K1_ID {target_k1_id} no encontrada en '{file_path}'.")
            return None
    except Exception as e:
        logger.error(f"Bob1: Error al buscar K1 en '{file_path}': {e}", exc_info=True)
        return None

async def call_alice2_for_ext_keys(k1_id: UUID, k1_value_base64: str, app_src: str, app_dst: str):
    logger.info(f"Bob1: Preparando llamada a Alice2 ({ALICE2_EXT_KEYS_URL}) para K1_ID: {k1_id}")
    payload_data = ExtKeyData(keys=[ExtKey_KeyItem(key_id=k1_id, value=k1_value_base64)], initiator_sae_id=app_src, target_sae_ids=[app_dst], ack_callback_url=MY_ACK_URL_FOR_ALICE2)
    payload_container = ExtKeyContainerPayload(ext_key_container=payload_data)
    try: json_str = payload_container.model_dump_json()
    except AttributeError: json_str = payload_container.json()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(ALICE2_EXT_KEYS_URL, content=json_str, headers={"Content-Type": "application/json"}, timeout=10.0)
    except Exception as e:
        logger.error(f"Bob1: Error en la llamada a Alice2 para K1_ID {k1_id}: {e}", exc_info=True)

async def notify_alice1_of_completion(alice1_url: str, k1_id: UUID, status: str, msg: Optional[str]):
    logger.info(f"Bob1: Preparando notificación final para Alice1 ({alice1_url}) para K1_ID: {k1_id}")
    payload = FinalNotificationToAlice1(k1_id=k1_id, overall_status=status, message=msg)
    try: json_str = payload.model_dump_json()
    except AttributeError: json_str = payload.json()
    try:
        async with httpx.AsyncClient() as client:
            await client.post(alice1_url, content=json_str, headers={"Content-Type": "application/json"}, timeout=10.0)
    except Exception as e:
        logger.error(f"Bob1: Error enviando notificación a Alice1 para K1_ID {k1_id}: {e}", exc_info=True)

app = FastAPI(title="Bob1 - Key Relay Intermediary (from BDD)")

@app.post("/relay_process_request", status_code=status.HTTP_202_ACCEPTED)
async def handle_relay_request_from_alice1(payload: RelayRequestFromAlice1, background_tasks: BackgroundTasks):
    logger.info(f"Bob1: Petición /relay_process_request RECIBIDA de Alice1 para K1_ID: {payload.k1_id}")
    k1_value_found = get_k1_value_from_bdd(BDD_B1_FILE_PATH, payload.k1_id)
    if not k1_value_found:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"K1_ID {payload.k1_id} no encontrada en la BDD de Bob1.")
    logger.info(f"Bob1: K1_value encontrado para K1_ID {payload.k1_id}. Almacenando URL de Alice1.")
    alice1_pending_notifications[str(payload.k1_id)] = payload.alice1_response_url
    background_tasks.add_task(call_alice2_for_ext_keys, payload.k1_id, k1_value_found, payload.app_src_id, payload.app_dst_id)
    return {"message": "Bob1: Petición de relay aceptada. Buscando K1 y procesando con Alice2."}

@app.post("/ack", status_code=status.HTTP_200_OK)
async def receive_ack_from_alice2(payload: AckContainerPayload, background_tasks: BackgroundTasks):
    ack_data = payload.ack_container
    logger.info(f"Bob1: ACK RECIBIDO de Alice2 ({ack_data.initiator_sae_id}) con estado: {ack_data.ack_status.value}")
    if not ack_data.key_ids:
        logger.error("Bob1: ACK de Alice2 sin key_ids. No se puede notificar a Alice1.")
        return {"status": "ACK de Alice2 sin key_ids."}
    relevant_k1_id = ack_data.key_ids[0].key_id
    alice1_url_to_notify = alice1_pending_notifications.pop(str(relevant_k1_id), None)
    if alice1_url_to_notify:
        logger.info(f"Bob1: URL de Alice1 encontrada para K1_ID {relevant_k1_id}. Preparando notificación final.")
        background_tasks.add_task(notify_alice1_of_completion, alice1_url_to_notify, relevant_k1_id, ack_data.ack_status.value, ack_data.message)
    else:
        logger.warning(f"Bob1: No se encontró URL de Alice1 para K1_ID {relevant_k1_id}.")
    return {"status": "ACK de Alice2 recibido y procesado por Bob1."}

@app.get("/")
async def read_root_bob1():
  return {"message": "Bob1 (clientFA_B1.py) está activo."}
