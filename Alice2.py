import base64
import logging
from typing import List, Optional, Dict, Any
from uuid import UUID
import json
import os
import httpx
from enum import Enum

from fastapi import FastAPI, status, BackgroundTasks
from pydantic import BaseModel

# Modelos Pydantic (ver contenido de contenedores en ETSI 020)
class KeyItem(BaseModel):
    key_id: UUID
    value: str
    extension: Optional[Dict[str, Any]] = None
class ExtKeyData(BaseModel):
    keys: List[KeyItem]
    initiator_sae_id: str
    target_sae_ids: List[str]
    ack_callback_url: str
    extension_mandatory: Optional[List[Dict[str, Any]]] = None
    extension_optional: Optional[List[Dict[str, Any]]] = None
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
    extension: Optional[Dict[str, Any]] = None
class AckData(BaseModel):
    key_ids: List[Ack_KeyIdItem]
    ack_status: AckStatusEnum
    initiator_sae_id: str
    target_sae_id: str
    message: Optional[str] = None
    extension: Optional[Dict[str, Any]] = None
class AckContainerPayload(BaseModel):
    ack_container: AckData

#Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [Alice2] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)
app = FastAPI(title="Alice2 - Key Processor, Bob2 Sender & ACK Sender")

# Rutas para obtener claves y interconectar con otros módulos (por defecto en localhost)
MY_SERVER_ID = "Alice2_Key_Server_001"
K2_FILE_PATH = "BDD_A2.txt"
BOB2_RELAYED_KEY_URL = os.getenv("BOB2_URL", "http://127.0.0.1:8003/send_relayed_key")

#Función auxiliar para cifrar K1 con K2
def apply_xor_cipher(data_bytes: bytes, key_bytes: bytes) -> bytes:
    if not key_bytes: raise ValueError("K2 no puede estar vacía.")
    if not data_bytes: raise ValueError("K1 no puede estar vacía.")
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])

#Función para obtener K2 de la base de datos
def get_fixed_k2_from_file(file_path: str) -> Optional[tuple[UUID, bytes]]:
    logger.info(f"Alice2: Leyendo K2 fija de: {file_path}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            line = f.readline().strip()
            if not line: return None
            k2_entry = json.loads(line)
            k2_id, k2_base64 = UUID(k2_entry["key_ID"]), k2_entry["key"]
            k2_bytes = base64.b64decode(k2_base64)
            if not k2_bytes: return None
            logger.info(f"Alice2: K2 fija leída: ID={k2_id}.")
            return k2_id, k2_bytes
    except Exception as e:
        logger.error(f"Alice2: Error leyendo K2 de '{file_path}': {e}", exc_info=True)
        return None
    
#Genera clave cifrada k_cypher (usa la auxiliar definida arriba)
def generate_k_cypher(k1_base64: str, k2_bytes: bytes, k1_id: UUID) -> Optional[bytes]:
    log_prefix = f"Alice2 K1 ID {k1_id}: "
    try:
        k1_bytes = base64.b64decode(k1_base64)
        logger.info(f"{log_prefix}K1 Original (string): '{k1_bytes.decode('utf-8', 'ignore')}'")
        k_cypher = apply_xor_cipher(k1_bytes, k2_bytes)
        logger.info(f"{log_prefix}K_Cypher (Base64): {base64.b64encode(k_cypher).decode('utf-8')}")
        return k_cypher
    except Exception as e:
        logger.error(f"{log_prefix}Error generando K_Cypher: {e}")
        return None
    

async def process_key_and_notify(key_data: ExtKeyData):
    logger.info(f"Alice2 [BG]: Proceso iniciado para initiator: {key_data.initiator_sae_id}")
    ack_status, ack_msg = AckStatusEnum.FAILED, "Error desconocido."
    processed_k1s_for_ack = [Ack_KeyIdItem(key_id=item.key_id) for item in key_data.keys] if key_data.keys else []
    k2_info = get_fixed_k2_from_file(K2_FILE_PATH)
    if not k2_info:
        ack_status, ack_msg = AckStatusEnum.K2_FETCH_ERROR, "Fallo al obtener K2."
    elif not key_data.keys:
        ack_status, ack_msg = AckStatusEnum.KEY_NOT_PRESENT, "No K1 en la petición."
    else:
        k1_item = key_data.keys[0]
        k2_id, k2_bytes = k2_info
        k_cypher = generate_k_cypher(k1_item.value, k2_bytes, k1_item.key_id)
        if not k_cypher:
            ack_status, ack_msg = AckStatusEnum.KCYPHER_GENERATION_ERROR, f"Fallo al generar K_Cypher para K1_ID: {k1_item.key_id}."
        else:
            payload_to_bob2 = {"k2_id": str(k2_id), "k_cifrada": base64.b64encode(k_cypher).decode('utf-8')} #A enviar a Bob2
            try:
                async with httpx.AsyncClient() as client:
                    resp_bob2 = await client.post(BOB2_RELAYED_KEY_URL, json=payload_to_bob2, timeout=10.0)
                    resp_bob2.raise_for_status()
                    ack_status, ack_msg = AckStatusEnum.RELAYED, f"K_Cypher para K1_ID {k1_item.key_id} enviada a Bob2."
            except Exception as e:
                ack_status, ack_msg = AckStatusEnum.BOB2_SEND_ERROR, f"Error enviando a Bob2: {str(e)[:100]}"
    ack_payload = AckContainerPayload(ack_container=AckData(key_ids=processed_k1s_for_ack, ack_status=ack_status, initiator_sae_id=MY_SERVER_ID, target_sae_id=key_data.initiator_sae_id, message=ack_msg))
    try: json_ack = ack_payload.model_dump_json()
    except AttributeError: json_ack = ack_payload.json()
    if key_data.ack_callback_url:
        logger.info(f"Alice2 [BG]: Enviando ACK a Bob1 ({key_data.ack_callback_url})")
        try:
            async with httpx.AsyncClient() as client:
                await client.post(key_data.ack_callback_url, content=json_ack, headers={"Content-Type": "application/json"}, timeout=10.0)
        except Exception as e:
            logger.error(f"Alice2 [BG]: Error enviando ACK a Bob1: {e}", exc_info=True)
    logger.info(f"Alice2 [BG]: Tarea finalizada para initiator: {key_data.initiator_sae_id}")

#Endpoint ext_keys, de ETSI 020
@app.post("/ext_keys", status_code=status.HTTP_202_ACCEPTED)
async def receive_ext_keys_from_bob1(payload: ExtKeyContainerPayload, background_tasks: BackgroundTasks):
    logger.info(f"Alice2: Petición /ext_keys RECIBIDA (originador: {payload.ext_key_container.initiator_sae_id})")
    background_tasks.add_task(process_key_and_notify, payload.ext_key_container)
    return {"message": "Alice2: Petición de K1 recibida. Procesando en segundo plano."}

@app.get("/")
async def read_root_alice2():
  return {"message": "Alice2 (serverFA_A2.py) está activa."}

# Para ejecutar: uvicorn Alice2:app --reload --host 0.0.0.0 --port 8000
