# cSpell:disable
import os

from pydantic import SecretStr

CAPTURE_CACHE_PATH = ""
RUN_LOG_PATH = ""
UHUBCTL_PATH = "/home/wireless-deep-fuzzer/3rd-party/uhubctl/uhubctls"

# WDissector configurations path
BT_WD_SM_CONFIG = "/home/wireless-deep-fuzzer/configs/bt_config.json"
BT_WD_MODEL_CONFIG = "/home/wireless-deep-fuzzer/configs/models/bt/sdp_rfcomm_query.json"
FIVEG_WD_SM_CONFIG = "/home/wireless-deep-fuzzer/configs/5gnr_gnb_config.json"
FIVEG_WD_MODEL_CONFIG = "/home/wireless-deep-fuzzer/configs/models/5gnr_gnb/nr-softmodem.json"
WIFI_WD_SM_CONFIG = "/home/wireless-deep-fuzzer/configs/wifi_ap_config.json"
WIFI_WD_MODEL_CONFIG = "/home/wireless-deep-fuzzer/configs/models/wifi_ap/wpa2_eap.json"

os.makedirs(CAPTURE_CACHE_PATH, exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/5gnr_gnb", exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/bt", exist_ok=True)
os.makedirs(f"{RUN_LOG_PATH}/wifi", exist_ok=True)

TSHARK_PATH = "/home/wireless-deep-fuzzer/bin/tshark"

# LLM API tokens
OPENAI_URL = ""
OPENAI_KEY = ""

GOOGLE_KEY = SecretStr("")

# cSpell:enable
