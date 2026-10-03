# cSpell:disable
import os

from pydantic import SecretStr

CAPTURE_CACHE_PATH = ""
RUN_LOG_PATH = ""
UHUBCTL_PATH = ""

# WDissector configurations path
BT_WD_SM_CONFIG = "configs/bt_config.json"
BT_WD_MODEL_CONFIG = "configs/models/bt/sdp_rfcomm_query.json"
FIVEG_WD_SM_CONFIG = "configs/5gnr_gnb_config.json"
FIVEG_WD_MODEL_CONFIG = "configs/models/5gnr_gnb/nr-softmodem.json"
WIFI_WD_SM_CONFIG = "configs/wifi_ap_config.json"
WIFI_WD_MODEL_CONFIG = "configs/models/wifi_ap/wpa2_eap.json"

if CAPTURE_CACHE_PATH:
    os.makedirs(CAPTURE_CACHE_PATH, exist_ok=True)
if RUN_LOG_PATH:
    os.makedirs(f"{RUN_LOG_PATH}/5gnr_gnb", exist_ok=True)
    os.makedirs(f"{RUN_LOG_PATH}/bt", exist_ok=True)
    os.makedirs(f"{RUN_LOG_PATH}/wifi", exist_ok=True)

TSHARK_PATH = ""
EDITCAP_PATH = ""

# LLM API configuration
LLM_API_URL = ""
LLM_API_KEY = SecretStr("")

# Compatibility aliases
OPENAI_URL = LLM_API_URL
OPENAI_KEY = LLM_API_KEY

GOOGLE_KEY = SecretStr("")

# cSpell:enable
