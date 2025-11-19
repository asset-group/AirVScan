import json
import math
import os
import random

# random.seed(123456) # normal
# random.seed(123457) # mut
random.seed(123458)  # reorder


class ModbusPacketGen:
    def __init__(self) -> None:
        pass

    def random_bytes(self, n: int):
        return random.randbytes(n)

    def random_int(self, min_val: int, max_val: int):
        # min and max are inclusive
        return random.randint(min_val, max_val)

    def random_bits(self, num_bits: int):
        # return as bytes, for the zero-filled values
        rand_bits = random.getrandbits(num_bits)
        return rand_bits.to_bytes(math.ceil(num_bits / 8))

    def pretty_bytes(self, b: bytes):
        return f"0x{b.hex()}"

    def gen_0x01(self):
        f_code = 0x01
        name = "Read Coils"

        # request
        while True:
            # Generate a valid starting address and quantity, need to fulfill
            # the end of address is less or equal to 0xFFFF
            starting_address = self.random_bytes(2)
            quantity_of_coils = self.random_int(1, 2000)  # num of bits

            if int.from_bytes(starting_address) + quantity_of_coils - 1 <= 0xFFFF:
                break

        # response
        byte_count = math.ceil(quantity_of_coils / 8)
        coil_status = self.random_bits(quantity_of_coils)  # byte

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Coils": quantity_of_coils,
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": byte_count,
            "Coil Status": self.pretty_bytes(coil_status),
        }

        return name, request_fields, response_fields

    def gen_0x02(self):
        f_code = 0x02
        name = "Read Discrete Inputs"

        # request
        while True:
            starting_address = self.random_bytes(2)
            quantity_of_inputs = self.random_int(1, 2000)

            if int.from_bytes(starting_address) + quantity_of_inputs - 1 <= 0xFFFF:
                break

        # response
        byte_count = math.ceil(quantity_of_inputs / 8)
        input_status = self.random_bits(quantity_of_inputs)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Inputs": quantity_of_inputs,
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": byte_count,
            "Input Status": self.pretty_bytes(input_status),
        }

        return name, request_fields, response_fields

    def gen_0x03(self):
        f_code = 0x03
        name = "Read Holding Registers"

        # request
        while True:
            starting_address = self.random_bytes(2)
            quantity_of_registers = self.random_int(1, 125)

            if int.from_bytes(starting_address) + quantity_of_registers - 1 <= 0xFFFF:
                break

        # response
        byte_count = quantity_of_registers * 2
        register_values = self.random_bytes(byte_count)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Registers": quantity_of_registers,
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": byte_count,
            "Register Values": self.pretty_bytes(register_values),
        }

        return name, request_fields, response_fields

    def gen_0x04(self):
        f_code = 0x04
        name = "Read Input Registers"

        # request
        while True:
            starting_address = self.random_bytes(2)
            quantity_of_registers = self.random_int(1, 125)

            if int.from_bytes(starting_address) + quantity_of_registers - 1 <= 0xFFFF:
                break

        # response
        byte_count = quantity_of_registers * 2
        input_registers = self.random_bytes(byte_count)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Input Registers": quantity_of_registers,
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": byte_count,
            "Input Registers": self.pretty_bytes(input_registers),
        }

        return name, request_fields, response_fields

    def gen_0x05(self):
        f_code = 0x05
        name = "Write Single Coil"

        # request
        output_address = self.random_bytes(2)
        output_value = random.choice([b"\xff\x00", b"\x00\x00"])  # ON or OFF

        # response is an echo of the request
        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Output Address": self.pretty_bytes(output_address),
            "Output Value": self.pretty_bytes(output_value),
        }

        response_fields = request_fields.copy()

        return name, request_fields, response_fields

    def gen_0x06(self):
        f_code = 0x06
        name = "Write Single Register"

        # request
        register_address = self.random_bytes(2)
        register_value = self.random_bytes(2)

        # response is an echo of the request
        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Register Address": self.pretty_bytes(register_address),
            "Register Value": self.pretty_bytes(register_value),
        }

        response_fields = request_fields.copy()

        return name, request_fields, response_fields

    def gen_0x0F(self):
        f_code = 0x0F
        name = "Write Multiple Coils"

        # request
        while True:
            starting_address = self.random_bytes(2)
            quantity_of_outputs = self.random_int(1, 1968)

            if int.from_bytes(starting_address) + quantity_of_outputs - 1 <= 0xFFFF:
                break

        byte_count = math.ceil(quantity_of_outputs / 8)
        outputs_value = self.random_bits(quantity_of_outputs)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Outputs": quantity_of_outputs,
            "Byte Count": byte_count,
            "Outputs Value": self.pretty_bytes(outputs_value),
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Outputs": quantity_of_outputs,
        }

        return name, request_fields, response_fields

    def gen_0x10(self):
        f_code = 0x10
        name = "Write Multiple Registers"

        # request
        while True:
            starting_address = self.random_bytes(2)
            quantity_of_registers = self.random_int(1, 123)

            if int.from_bytes(starting_address) + quantity_of_registers - 1 <= 0xFFFF:
                break

        byte_count = quantity_of_registers * 2
        registers_value = self.random_bytes(byte_count)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Registers": quantity_of_registers,
            "Byte Count": byte_count,
            "Registers Value": self.pretty_bytes(registers_value),
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Starting Address": self.pretty_bytes(starting_address),
            "Quantity of Registers": quantity_of_registers,
        }

        return name, request_fields, response_fields

    def gen_0x11(self):
        f_code = 0x11
        name = "Report Server ID"

        # request
        request_fields = {
            "Function Code": f"0x{f_code:02x}",
        }

        # response
        server_id = self.random_bytes(1)  # device specific
        run_indicator_status = random.choice([b"\x00", b"\xff"])  # OFF or ON
        additional_data = self.random_bytes(self.random_int(0, 240))  # device specific
        byte_count = 2 + len(additional_data)

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": byte_count,
            "Server ID": self.pretty_bytes(server_id),
            "Run Indicator Status": self.pretty_bytes(run_indicator_status),
            "Additional Data": self.pretty_bytes(additional_data),
        }

        return name, request_fields, response_fields

    def gen_0x14(self):
        f_code = 0x14
        name = "Read File Record"

        # --- Request and Response Generation ---
        # The total response length must be <= 0xF5 bytes.
        # We build the request while checking the size of the potential response.
        req_sub_requests = []
        resp_sub_responses = []
        total_resp_len = 0
        num_sub_requests = self.random_int(1, 3)  # Generate 1 to 3 sub-requests

        for _ in range(num_sub_requests):
            record_length = self.random_int(1, 10)  # Number of registers

            # File Resp Length (1 byte) + Ref Type (1 byte) + Record Data (N*2 bytes)
            potential_resp_sub_len = 2 + (record_length * 2)

            if total_resp_len + potential_resp_sub_len > 0xF5:
                break  # Stop adding sub-requests if PDU limit is exceeded

            total_resp_len += potential_resp_sub_len

            # Build Request Sub-request
            req_sub_requests.append(
                {
                    "Reference Type": 6,
                    "File Number": self.random_int(1, 0xFFFF),
                    "Record Number": self.random_int(0, 0x270F),
                    "Record Length": record_length,
                }
            )

            # Build Response Sub-response
            resp_sub_responses.append(
                {
                    "File Response Length": 1 + (record_length * 2),  # Ref Type + Record Data
                    "Reference Type": 6,
                    "Record Data": self.pretty_bytes(self.random_bytes(record_length * 2)),
                }
            )

        req_byte_count = len(req_sub_requests) * 7

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": req_byte_count,
            "Sub-Requests": req_sub_requests,
        }

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Response Data Length": total_resp_len,
            "Sub-Responses": resp_sub_responses,
        }

        return name, request_fields, response_fields

    def gen_0x15(self):
        f_code = 0x15
        name = "Write File Record"

        # The total request length must be <= 0xFB bytes.
        sub_requests = []
        total_req_len = 0
        num_sub_requests = self.random_int(1, 3)

        for _ in range(num_sub_requests):
            record_length = self.random_int(1, 10)  # Number of registers to write
            record_data = self.random_bytes(record_length * 2)

            # Ref Type (1) + File Num (2) + Rec Num (2) + Rec Len (2) + Data (N*2)
            sub_request_len = 7 + len(record_data)

            if total_req_len + sub_request_len > 0xFB:
                break  # Stop if PDU limit is exceeded

            total_req_len += sub_request_len

            sub_requests.append(
                {
                    "Reference Type": 6,
                    "File Number": self.random_int(1, 0xFFFF),
                    "Record Number": self.random_int(0, 0x270F),
                    "Record Length": record_length,
                    "Record Data": self.pretty_bytes(record_data),
                }
            )

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Request Data Length": total_req_len,
            "Sub-Requests": sub_requests,
        }

        # Response is an echo of the request
        response_fields = request_fields.copy()

        return name, request_fields, response_fields

    def gen_0x16(self):
        f_code = 0x16
        name = "Mask Write Register"

        # request
        reference_address = self.random_bytes(2)
        and_mask = self.random_bytes(2)
        or_mask = self.random_bytes(2)

        # response is an echo of the request
        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Reference Address": self.pretty_bytes(reference_address),
            "AND Mask": self.pretty_bytes(and_mask),
            "OR Mask": self.pretty_bytes(or_mask),
        }

        response_fields = request_fields.copy()

        return name, request_fields, response_fields

    def gen_0x17(self):
        f_code = 0x17
        name = "Read/Write Multiple Registers"

        # write request
        while True:
            write_starting_address = self.random_bytes(2)
            quantity_to_write = self.random_int(1, 121)
            if int.from_bytes(write_starting_address) + quantity_to_write - 1 <= 0xFFFF:
                break

        write_byte_count = quantity_to_write * 2
        write_registers_value = self.random_bytes(write_byte_count)

        # read request
        while True:
            read_starting_address = self.random_bytes(2)
            quantity_to_read = self.random_int(1, 125)
            if int.from_bytes(read_starting_address) + quantity_to_read - 1 <= 0xFFFF:
                break

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Read Starting Address": self.pretty_bytes(read_starting_address),
            "Quantity to Read": quantity_to_read,
            "Write Starting Address": self.pretty_bytes(write_starting_address),
            "Quantity to Write": quantity_to_write,
            "Write Byte Count": write_byte_count,
            "Write Registers Value": self.pretty_bytes(write_registers_value),
        }

        # response
        read_byte_count = quantity_to_read * 2
        read_registers_value = self.random_bytes(read_byte_count)

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": read_byte_count,
            "Read Registers Value": self.pretty_bytes(read_registers_value),
        }

        return name, request_fields, response_fields

    def gen_0x18(self):
        f_code = 0x18
        name = "Read FIFO Queue"

        # request
        fifo_pointer_address = self.random_bytes(2)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "FIFO Pointer Address": self.pretty_bytes(fifo_pointer_address),
        }

        # response
        fifo_count = self.random_int(0, 31)
        byte_count = 2 + fifo_count * 2  # FIFO Count + FIFO Value Register
        fifo_value_register = self.random_bytes(fifo_count * 2)

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "Byte Count": byte_count,
            "FIFO Count": fifo_count,
            "FIFO Value Register": self.pretty_bytes(fifo_value_register),
        }

        return name, request_fields, response_fields

    def gen_0x2B_0x0E(self):
        f_code = 0x2B
        mei_type = 0x0E
        name = "Read Device Identification"

        # request
        read_device_id_code = self.random_int(1, 4)
        object_id = self.random_int(0, 0xFF)

        request_fields = {
            "Function Code": f"0x{f_code:02x}",
            "MEI Type": mei_type,
            "Read Device ID Code": read_device_id_code,
            "Object ID": object_id,
        }

        # response
        conformity_level = self.random_int(1, 3)
        more_follows = random.choice([0x00, 0xFF])
        next_object_id = self.random_int(0, 0xFF) if more_follows == 0xFF else 0x00
        number_of_objects = self.random_int(1, 10)

        objects = []
        for _ in range(number_of_objects):
            obj_id = self.random_int(0, 0xFF)
            obj_length = self.random_int(1, 20)
            obj_value = self.random_bytes(obj_length)
            objects.append(
                {
                    "Object ID": obj_id,
                    "Object Length": obj_length,
                    "Object Value": self.pretty_bytes(obj_value),
                }
            )

        response_fields = {
            "Function Code": f"0x{f_code:02x}",
            "MEI Type": mei_type,
            "Read Device ID Code": read_device_id_code,
            "Conformity Level": conformity_level,
            "More Follows": more_follows,
            "Next Object ID": next_object_id,
            "Number of Objects": number_of_objects,
            "Objects": objects,
        }

        return name, request_fields, response_fields

    def gen(self, num: int):
        choices = [
            self.gen_0x01,
            self.gen_0x02,
            self.gen_0x03,
            self.gen_0x04,
            self.gen_0x05,
            self.gen_0x06,
            self.gen_0x0F,
            self.gen_0x10,
            self.gen_0x11,
            self.gen_0x14,
            self.gen_0x15,
            self.gen_0x16,
            self.gen_0x17,
            self.gen_0x18,
        ]

        pkts = []
        loc = 1
        for i in range(num // 2):
            name, req, res = random.choice(choices)()
            pkts.append({"pkt_loc": loc, "pkt_info": f"{name} Request", "pkt_fields": req})
            loc += 1
            pkts.append({"pkt_loc": loc, "pkt_info": f"{name} Response", "pkt_fields": res})
            loc += 1

        return pkts


if __name__ == "__main__":
    modbus_gen = ModbusPacketGen()

    for root, dirs, files in os.walk("captures_new/mock-modbus/reorder"):
        for d in dirs:
            packets_json_path = os.path.join(root, d, "packets.json")
            with open(packets_json_path, "w") as f:
                json.dump(modbus_gen.gen(12), f, indent=4)
