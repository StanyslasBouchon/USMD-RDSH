from usmd_rdsh.proto.base.bitvec import Msb
from usmd_rdsh.proto.base.encoder import BitEncoder
from usmd_rdsh.proto.base.event import EventEncoder
from usmd_rdsh.proto.nndp.base.env import MAGIC, HereIAmData
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result


class HereIAmPacket(EventEncoder[Msb]):
    """Here I Am packet class."""

    def __init__(self, data: HereIAmData):
        super().__init__()

        self.encoder = BitEncoder[Msb]()
        self.data = data

    def encode(self) -> Result[None, Error]:
        Result.hide()

        if len(self.data.node_id) > 1 << 16:
            return Result.Err(
                Error.new(ErrorKind.SIZE_CONSTRAINT_VIOLATION, "Node name is too long")
            )

        self.encoder.add_data(MAGIC, 16)
        self.encoder.add_data(self.data.version, 8)
        self.encoder.add_data(len(self.data.node_id), 16)
        self.encoder.add_bytes(self.data.node_id.encode("utf-8"))
        self.encoder.add_data(self.data.next_hia_pkt_time, 64)
        self.encoder.add_data(self.data.state.value, 16)

        return Result.reveal()

    def get_encoder(self) -> BitEncoder[Msb]:
        return self.encoder

    def get_event(self) -> int:
        return 0x0001
