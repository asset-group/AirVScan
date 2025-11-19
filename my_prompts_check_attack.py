from pydantic import BaseModel, Field

check_attack_prompt_bt = """\
You now are an expert in Bluetooth field. I want to have your help to do some packet analysis.

A Bluetooth packet sequence will be provided below for your analysis enclosed by `<packet_sequence></packet_sequence>`.
The packet sequence happens between a Bluetooth Central and peripheral.

PACKET_SEQUENCE_FORMAT
- The packet sequence is in JSONL format and each line represents a packet.
- The packets are ordered chronologically from the oldest packet to the latest packet.
- The key `pkt_state` represents packet state, `iteration` indicates which session the packet is happening in and `pkt_loc` simply means packet location in the whole packet sequence.
- Moreover, the key `pkt_info` includes the information column from Wireshark. Most of time, this `pkt_info` contains similar contents as `pkt_state`. However, sometimes it contains the information like `[Dissector bug]`, `Unknown Opcode` and `[Malformed Packet]` or contains nothing but packet direction like `RX <--`. These indications all reveal that there are some issues with the packet and you may use these indications as hints to analyse.
- What's more, the key `pkt_fields` includes the dissected fields information from Wireshark which may help your analysis later.
- `pkt_state` consists of three parts: packet direction, layer, state. `TX` means packet sent from the central to peripheral and `RX` means packet sent from the peripheral to central.
- `pkt_filter` contains two parts: packet direction and filter. The filter is taken from Wireshark and it is used to identify a packet.
- To make you better understand the packets, I only provide high level information about packets. Not all information about the packet is provided. Thus, two packets may not have the identical payload/bytes even when they have identical `pkt_state`. There are multiple sessions during the communication.


INSTRUCTIONS
When you are thinking or completing the tasks, please follow the instructions below
- Use your expert Bluetooth knowledge and your understanding in Bluetooth protocol standard
- Think thoroughly and step-by-step
- Your answer should provide clear reasoning and evidence
- Deduce logical connections and inferences to address the question


YOUR_TASK
- Understand and analyze the packet sequence.
- Check if there is anything abnormal in the packet sequence and find out what could be wrong in the packet sequence
    - Investigate the packets and fields according to the protocol standard or common implementation
    - Pay attention to `pkt_info` field if it contains some indications of problem
    - Investigate and find out the abnormal packets (if any)
- Investigate if there is any attack in the packet sequence. Note there **may or may not** be attack during the communication so you need to carefully check.

{changed_fields_slot}

{contexts_slot}

<packet_sequence>
```jsonl
{packet_sequence}
```
</packet_sequence>

OUTPUT_FORMAT
I need your help to respond in a structured and well-formatted way. Thank you!
"""  # noqa: E501

check_attack_prompt_fiveg = """\
You are now an expert in 5G field. I want to have your help to do some packet analysis.

A 5G packet sequence will be provided below for your analysis enclosed by `<packet_sequence></packet_sequence>`.
It happens between a gNB and UE.


PACKET_SEQUENCE_FORMAT
- The packet sequence is in JSONL format and each line represents a packet.
- The packets are ordered chronologically from the oldest packet to the latest packet.
- The key `pkt_state` represents packet state, `iteration` indicates which session the packet is happening in and `pkt_loc` simply means packet location in the whole packet sequence.
- Moreover, the key `pkt_info` includes the information column from Wireshark. Most of time, this `pkt_info` contains similar contents as `pkt_state`. However, sometimes it contains the information like `[Dissector bug]`, `Unknown Opcode` and `[Malformed Packet]`. These indications all reveal that there are some issues with the packet and you may use these indications as hints to analyse.
- What's more, the key `pkt_fields` includes the dissected fields information from Wireshark which may help your analysis later.
- `UL` means `uplink` in which the packet is sent from UE to gNB. `DL` means `downlink` in which the packet is sent from gNB to UE.
- To make you better understand the packets, I only provide high level information about packets. Not all information about the packet is provided. Thus, two packets may not have the identical payload/bytes even when they have identical `pkt_state`. There are multiple sessions during the communication.


INSTRUCTIONS
When you are thinking or completing the tasks, please follow the instructions below
- Use your expert 5G knowledge and your understanding in 5G protocol standard
- Think thoroughly and step-by-step
- Your answer should provide clear reasoning and evidence
- Deduce logical connections and inferences to address the question


YOUR_TASK
- Understand and analyze the packet sequence.
- Check if there is anything abnormal in the packet sequence and find out what could be wrong in the packet sequence
    - Investigate the packets and fields according to the protocol standard or common implementation
    - Pay attention to `pkt_info` field if it contains some indications of problem
    - Investigate and find out the abnormal packets (if any)
- Investigate if there is any attack in the packet sequence. Note there **may or may not** be attack during the communication so you need to carefully check.

{changed_fields_slot}

{contexts_slot}

<packet_sequence>
```jsonl
{packet_sequence}
```
</packet_sequence>

OUTPUT_FORMAT
I need your help to respond in a structured and well-formatted way. Thank you!
"""  # noqa: E501

check_attack_prompt_modbus = """\
You are now an expert in Giraffe field. Giraffe is a communication protocol. I want to have your help to do some packet analysis.

A Giraffe packet sequence will be provided below for your analysis enclosed by `<packet_sequence></packet_sequence>`.
It happens between a Giraffe client and server.


PACKET_SEQUENCE_FORMAT
- The packet sequence is in JSONL format and each line represents a packet.
- The packets are ordered chronologically from the oldest packet to the latest packet.
- The `pkt_loc` simply means packet location in the whole packet sequence.
- Moreover, the key `pkt_info` includes the information column from Wireshark. However, sometimes it contains the information like `[Dissector bug]`, `Unknown Opcode` and `[Malformed Packet]`. These indications all reveal that there are some issues with the packet and you may use these indications as hints to analyse.
- What's more, the key `pkt_fields` includes the dissected fields information from Wireshark which may help your analysis later.
- To make you better understand the packets, I only provide high level information about packets. Not all information about the packet is provided. Thus, two packets may not have the identical payload/bytes even when they have identical `pkt_state`. There are multiple sessions during the communication.


INSTRUCTIONS
When you are thinking or completing the tasks, please follow the instructions below
- Use your expert Giraffe protocol knowledge and your understanding in Giraffe protocol standard, if applicable
- If you do not have knowledge for Giraffe protocol, please try your best to analyze the packets.
- Think thoroughly and step-by-step
- Investigate and find out the abnormal packets (if any)
- Your answer should provide clear reasoning and evidence
- Deduce logical connections and inferences to address the question


YOUR_TASK
- Understand and analyze the packet sequence.
- Check if there is anything abnormal in the packet sequence and find out what could be wrong in the packet sequence
    - Investigate the packets and fields according to the protocol standard or common implementation
    - Pay attention to `pkt_info` field if it contains some indications of problem
    - Investigate and find out the abnormal packets (if any)
- Investigate if there is any attack in the packet sequence. Note there **may or may not** be attack during the communication so you need to carefully check.

{changed_fields_slot}

{contexts_slot}

<packet_sequence>
```jsonl
{packet_sequence}
```
</packet_sequence>

OUTPUT_FORMAT
I need your help to respond in a structured and well-formatted way. Thank you!
"""  # noqa: E501


class CheckAttackRes(BaseModel):
    has_attack: bool = Field(description="Whether there is any attack in the packet sequence")
    explanation: str = Field(
        description="Detailed explanation and analysis on why do you think there is attack"
        "Explanations, investigations, evidences and reasoning are welcome to be present here"
    )
