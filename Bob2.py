import logging
from typing import Optional
from uuid import UUID
import base64 
import json   
import os     

from fastapi import FastAPI, status, HTTPException
from pydantic import BaseModel

# Configuración básica de Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [Bob2] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="Bob2 - Relayed Key Receiver & Decryptor")
BDD_B2_FILE_PATH = "BDD_B2.txt" #idéntico al que tiene Alice2

# Modelo Pydantic para los datos de entrada del endpoint /send_relayed_key
class RelayedKeyPayload(BaseModel):
    k2_id: UUID       # El ID de la clave K2 que se usó para el XOR original
    k_cifrada: str  # K_Cypher (K1 XOR K2) en formato Base64

# Función auxiliar para la operación XOR
def apply_xor_cipher(data_bytes: bytes, key_bytes: bytes) -> bytes:
    #Aplica un cifrado XOR. Si las longitudes son diferentes, se ajusta al más corto
    if not key_bytes:
        raise ValueError("La clave K2 para XOR no puede estar vacía.")
    if not data_bytes: 
        raise ValueError("Los datos K_cifrada para XOR no pueden estar vacíos.")
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data_bytes)])

# Función para obtener K2 (valor) desde BDD_B2.txt usando K2_ID (con gestión de errores)
def get_k2_value_from_bdd(file_path: str, target_k2_id: UUID) -> Optional[bytes]:

    logger.info(f"Buscando K2 en '{file_path}' para K2_ID: {target_k2_id}")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line_number, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entry_id_str = entry.get("key_ID")
                    k2_value_base64 = entry.get("key")

                    if not entry_id_str or k2_value_base64 is None:
                        logger.warning(f"Línea {line_number} en '{file_path}' con formato incorrecto: {line}")
                        continue
                    
                    if UUID(entry_id_str) == target_k2_id:
                        logger.info(f"K2_ID {target_k2_id} encontrada en '{file_path}'.")
                        if not k2_value_base64:
                            logger.warning(f"K2 (ID: {target_k2_id}) en '{file_path}' tiene valor Base64 vacío.")
                            return None
                        
                        k2_bytes_decodificados = base64.b64decode(k2_value_base64)
                        if not k2_bytes_decodificados:
                            logger.warning(f"K2 (ID: {target_k2_id}) decodificada de Base64 está vacía.")
                            return None
                        
                        logger.info(f"K2 (ID: {target_k2_id}) obtenida y decodificada (len={len(k2_bytes_decodificados)} bytes).")
                        return k2_bytes_decodificados
                
                except json.JSONDecodeError:
                    logger.warning(f"Línea {line_number} en '{file_path}' no es JSON válido.")
                except ValueError:
                    logger.warning(f"Línea {line_number} en '{file_path}' tiene un key_ID no UUID.")
                except (base64.binascii.Error, TypeError) as b64e:
                    logger.error(f"Error al decodificar K2 Base64 de la línea {line_number} para K2_ID {target_k2_id}: {b64e}")
                    return None

            logger.warning(f"K2_ID {target_k2_id} no encontrada en '{file_path}'.")
            return None
    except FileNotFoundError:
        logger.error(f"Archivo BDD_B2 ('{file_path}') no encontrado.")
        return None
    except Exception as e:
        logger.error(f"Error general al leer K2 de '{file_path}': {e}", exc_info=True)
        return None

# Definición del Endpoint /send_relayed_key
@app.post("/send_relayed_key", status_code=status.HTTP_200_OK)
async def receive_relayed_key(payload: RelayedKeyPayload):
    """
    Endpoint para que Bob2 reciba K2_ID y K_cifrada.
    Busca K2 en su BDD, descifra K_cifrada para obtener K1.
    """
    logger.info(f"Datos recibidos en /send_relayed_key:")
    logger.info(f"  K2_ID recibida: {payload.k2_id}")
    logger.info(f"  K_cifrada (Base64, primeros 30 chars): {payload.k_cifrada[:30]}...")

    # 1. Obtener K2 (valor en bytes) de BDD_B2.txt usando la K2_ID recibida
    k2_from_file_bytes = get_k2_value_from_bdd(BDD_B2_FILE_PATH, payload.k2_id)

    if not k2_from_file_bytes:
        logger.error(f"No se pudo obtener K2 de BDD_B2.txt para K2_ID: {payload.k2_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail=f"K2 no encontrada o no se pudo procesar para K2_ID: {payload.k2_id}"
        )

    # 2. Decodificar K_cifrada (K1 XOR K2) de Base64
    try:
        k_cypher_bytes = base64.b64decode(payload.k_cifrada)
        if not k_cypher_bytes:
            logger.error("K_cifrada recibida está vacía después de decodificar Base64.")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="K_cifrada (Base64) es inválida o vacía.")
        logger.info(f"K_cifrada decodificada (len={len(k_cypher_bytes)} bytes).")
    except (base64.binascii.Error, ValueError) as e:
        logger.error(f"Error al decodificar K_cifrada de Base64: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"K_cifrada (Base64) inválida: {e}")

    # 3. Descifrar K_Cypher para obtener K1 (K1_restaurada = K_Cypher XOR K2_from_file)
    try:
        k1_restaurada_bytes = apply_xor_cipher(k_cypher_bytes, k2_from_file_bytes)
        k1_restaurada_base64 = base64.b64encode(k1_restaurada_bytes).decode('utf-8')
        logger.info(f"K1 restaurada (len={len(k1_restaurada_bytes)} bytes, Base64: {k1_restaurada_base64}).")
        
        try:
            k1_restaurada_string = k1_restaurada_bytes.decode('utf-8')
            logger.info(f"VERIFICACIÓN K1 Restaurada (string): '{k1_restaurada_string}'") 
        except UnicodeDecodeError:
            logger.info(f"VERIFICACIÓN K1 Restaurada (bytes, no es decodificable como UTF-8).") 
            k1_restaurada_string = None 

    except ValueError as e: 
        logger.error(f"Error al aplicar XOR para descifrar K1: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Error durante el descifrado XOR: {e}")
    except Exception as e:
        logger.error(f"Error inesperado durante el descifrado: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error interno inesperado durante el descifrado.")

    return {
        "status": "success",
        "message": "K_cifrada recibida y K1 restaurada por Bob2.",
        "received_k2_id": payload.k2_id,
        "k1_restored_preview_utf8": k1_restaurada_string if k1_restaurada_string else "N/A (no es UTF-8 o error)",
    }

@app.get("/")
async def read_root_bob2():
  return {"message": "Bob2 está activo y esperando en /send_relayed_key"}

#en consola: uvicorn Bob2:app --reload --host 0.0.0.0 --port 8003
