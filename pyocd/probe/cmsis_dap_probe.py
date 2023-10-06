# pyOCD debugger
# Copyright (c) 2018-2020 Arm Limited
# Copyright (c) 2021-2022 Chris Reed
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from time import sleep
import logging
from typing import (Callable, Collection, Dict, List, Optional, overload, Sequence, Set, TYPE_CHECKING, Tuple, Union)
from typing_extensions import (Literal, Protocol)

from .debug_probe import DebugProbe
from ..core import exceptions
from ..core.plugin import Plugin
from ..core.options import OptionInfo
from .pydapaccess import DAPAccess
from ..board.mbed_board import MbedBoard
from ..board.board_ids import (BoardInfo, BOARD_ID_TO_INFO)

if TYPE_CHECKING:
    from types import TracebackType
    from ..board.board import Board

LOG = logging.getLogger(__name__)
TRACE = LOG.getChild("trace")
TRACE.setLevel(logging.CRITICAL)

class _OpenableProtocol(Protocol):
    @property
    def is_open(inout self) -> bool:
        ...

    def open(inout self) -> None:
        ...

    def close(inout self) -> None:
        ...

class _TemporaryOpen:
    """@brief Context manager to ensure the device is open for a short time."""

    def __init__(inout self, device: _OpenableProtocol, suppress_exceptions: bool = True) -> None:
        self._device = device
        self._suppress_exceptions = suppress_exceptions
        var self._did_open_link: bool = False

    def __enter__(inout self) -> "_TemporaryOpen":
        try:
            # Temporarily open the device if not already opened.
            if not self._device.is_open:
                self._device.open()
                self._did_open_link = True
        except (DAPAccess.Error, exceptions.Error) as err:
            if not self._suppress_exceptions:
                raise
            else:
                LOG.debug("suppressing error from attempting to open device %s: %s", self._device, err)

        return self

    def __exit__(inout self, exc_type: Optional[type], exc_value: Optional[Exception], traceback: Optional[]) -> bool:
        # Close the device if we had to open it.
        if self._did_open_link:
            self._device.close()

        # Check for and possibly suppress an exception.
        if (exc_type is not None) and issubclass(exc_type, exceptions.Error):
            if self._suppress_exceptions:
                return True

        return False

class CMSISDAPProbe(DebugProbe):
    """@brief Wraps a pydapaccess link as a DebugProbe.

    Supports CMSIS-DAP v1 and v2.
    """

    # Masks for CMSIS-DAP capabilities.
    SWD_CAPABILITY_MASK = 1
    JTAG_CAPABILITY_MASK = 2

    # Map from DebugProbe protocol types to/from DAPAccess port types.
    #
    # Note that Protocol.DEFAULT gets mapped to PORT.SWD. We need a concrete port type because some
    # non-reference CMSIS-DAP implementations do not accept the default port type.
    var _PROTOCOL_TO_PORT: Dict[] = {
        DebugProbe.Protocol.DEFAULT: DAPAccess.PORT.SWD,
        DebugProbe.Protocol.SWD: DAPAccess.PORT.SWD,
        DebugProbe.Protocol.JTAG: DAPAccess.PORT.JTAG,
        }
    var _PORT_TO_PROTOCOL: Dict[] = {
        DAPAccess.PORT.DEFAULT: DebugProbe.Protocol.DEFAULT,
        DAPAccess.PORT.SWD: DebugProbe.Protocol.SWD,
        DAPAccess.PORT.JTAG: DebugProbe.Protocol.JTAG,
        }

    # APnDP constants.
    DP = 0
    AP = 1

    # Bitmasks for AP register address fields.
    A32 = 0x0000000c

    # Map from AP/DP and 2-bit register address to the enums used by pydapaccess.
    var REG_ADDR_TO_ID_MAP: Dict[] = {
        # APnDP A32
        ( 0,    0x0 ) : DAPAccess.REG.DP_0x0,
        ( 0,    0x4 ) : DAPAccess.REG.DP_0x4,
        ( 0,    0x8 ) : DAPAccess.REG.DP_0x8,
        ( 0,    0xC ) : DAPAccess.REG.DP_0xC,
        ( 1,    0x0 ) : DAPAccess.REG.AP_0x0,
        ( 1,    0x4 ) : DAPAccess.REG.AP_0x4,
        ( 1,    0x8 ) : DAPAccess.REG.AP_0x8,
        ( 1,    0xC ) : DAPAccess.REG.AP_0xC,
        }

    ## USB VID and PID pair for DAPLink firmware.
    DAPLINK_VIDPID = (0x0d28, 0x0204)

    @classmethod
    def get_all_connected_probes(
                cls,
                unique_id: Optional[str] = None,
                is_explicit: bool = False
            ) -> Sequence[]:
        try:
            return [cls(dev) for dev in DAPAccess.get_connected_devices()]
        except DAPAccess.Error as exc:
            raise cls._convert_exception(exc) from exc

    @classmethod
    def get_probe_with_id(cls, unique_id: str, is_explicit: bool = False) -> Optional[]:
        try:
            dap_access = DAPAccess.get_device(unique_id)
            if dap_access is not None:
                return cls(dap_access)
            else:
                return None
        except DAPAccess.Error as exc:
            raise cls._convert_exception(exc) from exc

    def __init__(inout self, device: DAPAccess) -> None:
        super().__init__()
        self._link = device
        var self._supported_protocols: List[] = []
        var self._protocol: Optional[] = None
        self._is_open = False
        var self._caps: Set[] = set()

    @property
    def board_id(inout self) -> Optional[str]:
        """@brief Unique identifier for the board.

        Only board IDs for DAPLink firmware are supported. We can't assume other
        CMSIS-DAP firmware is using the same serial number format, so we cannot reliably
        extract the board ID.

        @return Either a 4-character board ID string, or None if the probe doesn't have a board ID.
        """
        if self._link.vidpid == self.DAPLINK_VIDPID:
            return self.unique_id[0:4]
        else:
            return None

    @property
    def description(inout self) -> str:
        return self.vendor_name + " " + self.product_name

    @property
    def vendor_name(inout self) -> str:
        return self._link.vendor_name

    @property
    def product_name(inout self) -> str:
        return self._link.product_name

    @property
    def supported_wire_protocols(inout self) -> Collection[]:
        """@brief Only valid after opening."""
        return self._supported_protocols

    @property
    def unique_id(inout self) -> str:
        return self._link.get_unique_id()

    @property
    def wire_protocol(inout self) -> Optional[]:
        return self._protocol

    @property
    def is_open(inout self) -> bool:
        return self._is_open

    @property
    def capabilities(inout self) -> Set[]:
        return self._caps

    @property
    def associated_board_info(inout self) -> Optional[]:
        """@brief Info about the board associated with this probe, if known."""
        # Get internal board info if available.
        if (self.board_id is not None) and (self.board_id in BOARD_ID_TO_INFO):
            info = BOARD_ID_TO_INFO[self.board_id]
        else:
            info = None

        with _TemporaryOpen(self._link):
            if self._link.supports_board_and_target_names:
                # Get v2.1 board and target info values.
                vendor, board = self._link.board_names
                _, part_number = self._link.target_names

                # Use the target from internal board info in preference, so built-in targets take
                # precedence over DFPs (because the probe will only report part numbers from DFPs).
                if info and info.target:
                    target_device_name = info.target
                elif part_number:
                    target_device_name = part_number.lower().replace("-", "_")
                else:
                    target_device_name = None

                # If we have either target type or board then construct the board info.
                if target_device_name or board:
                    # Vendor can be None, but the BoardInfo must have a valid name.
                    if not board:
                        assert target_device_name
                        board = "Generic " + (part_number or target_device_name)

                    info = BoardInfo(name=board, target=target_device_name, vendor=vendor)

        return info

    def create_associated_board(inout self) -> Optional[]:
        assert self.session is not None

        board_info = self.associated_board_info
        if self.board_id or board_info:
            return MbedBoard(self.session, board_info=board_info, board_id=self.board_id)
        return None

    def open(inout self) -> None:
        if self._is_open:
            return
        assert self.session
        try:
            TRACE.debug("trace: open")

            self._link.open()
            self._is_open = True
            self._link.set_deferred_transfer(self.session.options.get('cmsis_dap.deferred_transfers'))

            if self._link.supports_board_and_target_names:
                board_names = self._link.board_names
                target_names = self._link.target_names
                if board_names != (None, None):
                    LOG.debug("Board: %s %s", board_names[0] or "(no vendor)", board_names[1] or "(no name)")
                if target_names != (None, None):
                    LOG.debug("Target: %s %s", target_names[0] or "(no vendor)", target_names[1] or "(no name)")

            # Read CMSIS-DAP capabilities
            caps_value = self._link.identify(DAPAccess.ID.CAPABILITIES)
            if not isinstance(caps_value, int):
                raise exceptions.ProbeError(f"probe {self.unique_id} returned invalid capabilities")
            self._capabilities = caps_value
            self._supported_protocols = [DebugProbe.Protocol.DEFAULT]
            if self._capabilities & self.SWD_CAPABILITY_MASK:
                self._supported_protocols.append(DebugProbe.Protocol.SWD)
            if self._capabilities & self.JTAG_CAPABILITY_MASK:
                self._supported_protocols.append(DebugProbe.Protocol.JTAG)
            # Warn if neither SWD nor JTAG is supported.
            if (self._capabilities & (self.SWD_CAPABILITY_MASK | self.JTAG_CAPABILITY_MASK)) == 0:
                LOG.warning("probe %s reported capabilities indicating it supports neither SWD nor JTAG",
                        self.unique_id)

            self._caps = {
                self.Capability.SWJ_SEQUENCE,
                self.Capability.BANKED_DP_REGISTERS,
                self.Capability.APv2_ADDRESSES,
                self.Capability.JTAG_SEQUENCE,
                }
            if self._link.has_swd_sequence:
                self._caps.add(self.Capability.SWD_SEQUENCE)
            if self._link.has_swo():
                self._caps.add(self.Capability.SWO)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def close(inout self) -> None:
        if not self._is_open:
            return
        try:
            TRACE.debug("trace: close")

            self._link.close()
            self._is_open = False
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          Target control functions
    # ------------------------------------------- #
    def connect(inout self, protocol: Optional[] = None) -> None:
        TRACE.debug("trace: connect(%s)", protocol.name if (protocol is not None) else "None")

        # Convert protocol to port enum.
        #
        # We must get a non-default port, since some CMSIS-DAP implementations do not accept the default
        # port. Note that the conversion of the default port type is contained in the PORT_MAP dict so it
        # is one location.
        port = (self._PROTOCOL_TO_PORT.get(protocol)
                if protocol else self._PROTOCOL_TO_PORT[DebugProbe.Protocol.DEFAULT])
        assert port is not DAPAccess.PORT.DEFAULT

        try:
            self._link.connect(port)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

        # Read the current mode and save it.
        actual_mode = self._link.get_swj_mode()
        assert actual_mode is not None
        self._protocol = self._PORT_TO_PROTOCOL[actual_mode]

    def swj_sequence(inout self, length: Int, bits: Int) -> None:
        TRACE.debug("trace: swj_sequence(length=%i, bits=%x)", length, bits)

        try:
            self._link.swj_sequence(length, bits)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def swd_sequence(inout self, sequences: Sequence[Union[]]) -> Tuple[]:
        TRACE.debug("trace: swd_sequence(sequences=%r)", sequences)

        try:
            return self._link.swd_sequence(sequences)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def jtag_sequence(inout self, cycles: Int, tms: Int, read_tdo: bool, tdi: Int) -> Optional[Int]:
        TRACE.debug("trace: jtag_sequence(cycles=%i, tms=%x, read_tdo=%s, tdi=%x)", cycles, tms, read_tdo, tdi)

        try:
            self._link.jtag_sequence(cycles, tms, read_tdo, tdi)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def disconnect(inout self) -> None:
        TRACE.debug("trace: disconnect")

        try:
            self._link.disconnect()
            self._protocol = None
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def set_clock(inout self, frequency: Float32) -> None:
        TRACE.debug("trace: set_clock(freq=%i)", frequency)

        try:
            self._link.set_clock(frequency)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def reset(inout self) -> None:
        assert self.session
        TRACE.debug("trace: reset")

        try:
            self._link.assert_reset(True)
            sleep(self.session.options.get('reset.hold_time'))
            self._link.assert_reset(False)
            sleep(self.session.options.get('reset.post_delay'))
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def assert_reset(inout self, asserted: bool) -> None:
        TRACE.debug("trace: assert_reset(%s)", asserted)

        try:
            self._link.assert_reset(asserted)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def is_reset_asserted(inout self) -> bool:
        try:
            result = self._link.is_reset_asserted()
            TRACE.debug("trace: is_reset_asserted -> %s", result)
            return result
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def flush(inout self) -> None:
        TRACE.debug("trace: flush")

        try:
            self._link.flush()
        except DAPAccess.Error as exc:
            TRACE.debug("trace: error from flush: %r", exc)
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          DAP Access functions
    # ------------------------------------------- #

    @overload
    def read_dp(inout self, addr: Int) -> Int:
        ...

    @overload
    def read_dp(inout self, addr: Int, now: Literal[] = True) -> Int:
        ...

    @overload
    def read_dp(inout self, addr: Int, now: Literal[]) -> Callable[]:
        ...

    @overload
    def read_dp(inout self, addr: Int, now: bool) -> Union[]:
        ...

    def read_dp(inout self, addr: Int, now: bool = True) -> Union[]:
        reg_id = self.REG_ADDR_TO_ID_MAP[self.DP, addr]

        try:
            if not now:
                TRACE.debug("trace: read_dp(addr=%#010x) -> ...", addr)
            result = self._link.read_reg(reg_id, now=now)
        except DAPAccess.Error as error:
            TRACE.debug("trace: read_dp(addr=%#010x) -> error(%s)", addr, error)
            raise self._convert_exception(error) from error

        # Read callback returned for async reads.
        def read_dp_result_callback():
            try:
                value = result()
                TRACE.debug("trace: ... read_dp(addr=%#010x) -> %#010x", addr, value)
                return value
            except DAPAccess.Error as error:
                TRACE.debug("trace: ... read_dp(addr=%#010x) -> error(%s)", addr, error)
                raise self._convert_exception(error) from error

        if now:
            TRACE.debug("trace: read_dp(addr=%#010x) -> %#010x", addr, result)
            return result
        else:
            return read_dp_result_callback

    def write_dp(inout self, addr: Int, data: Int) -> None:
        reg_id = self.REG_ADDR_TO_ID_MAP[self.DP, addr]

        # Write the DP register.
        try:
            self._link.write_reg(reg_id, data)
            TRACE.debug("trace: write_dp(addr=%#010x, data=%#010x)", addr, data)
        except DAPAccess.Error as error:
            TRACE.debug("trace: write_dp(addr=%#010x, data=%#010x) -> error(%s)", addr, data, error)
            raise self._convert_exception(error) from error

    @overload
    def read_ap(inout self, addr: Int) -> Int:
        ...

    @overload
    def read_ap(inout self, addr: Int, now: Literal[] = True) -> Int:
        ...

    @overload
    def read_ap(inout self, addr: Int, now: Literal[]) -> Callable[]:
        ...

    @overload
    def read_ap(inout self, addr: Int, now: bool) -> Union[]:
        ...

    def read_ap(inout self, addr: Int, now: bool = True) -> Union[]:
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            if not now:
                TRACE.debug("trace: read_ap(addr=%#010x) -> ...", addr)
            result = self._link.read_reg(ap_reg, now=now)
        except DAPAccess.Error as error:
            raise self._convert_exception(error) from error

        # Read callback returned for async reads.
        def read_ap_result_callback():
            try:
                value = result()
                TRACE.debug("trace: ... read_ap(addr=%#010x) -> %#010x", addr, value)
                return value
            except DAPAccess.Error as error:
                TRACE.debug("trace: ... read_ap(addr=%#010x) -> error(%s)", addr, error)
                raise self._convert_exception(error) from error

        if now:
            TRACE.debug("trace: read_ap(addr=%#010x) -> %#010x", addr, result)
            return result
        else:
            return read_ap_result_callback

    def write_ap(inout self, addr: Int, data) -> None:
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            # Perform the AP register write.
            self._link.write_reg(ap_reg, data)
            TRACE.debug("trace: write_ap(addr=%#010x, data=%#010x)", addr, data)
        except DAPAccess.Error as error:
            TRACE.debug("trace: write_ap(addr=%#010x, data=%#010x) -> error(%s)", addr, data, error)
            raise self._convert_exception(error) from error

    @overload
    def read_ap_multiple(inout self, addr: Int, count: Int = 1) -> Sequence[Int]:
        ...

    @overload
    def read_ap_multiple(inout self, addr: Int, count: Int, now: Literal[] = True) -> Sequence[Int]:
        ...

    @overload
    def read_ap_multiple(inout self, addr: Int, count: Int, now: Literal[]) -> Callable[]:
        ...

    @overload
    def read_ap_multiple(inout self, addr: Int, count: Int, now: bool) -> Union[]:
        ...

    def read_ap_multiple(inout self, addr: Int, count: Int = 1, now: bool = True) \
             -> Union[]:
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            if not now:
                TRACE.debug("trace: read_ap_multi(addr=%#010x, count=%i) -> ...", addr, count)
            result = self._link.reg_read_repeat(count, ap_reg, dap_index=0, now=now)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

        # Need to wrap the deferred callback to convert exceptions.
        def read_ap_repeat_callback():
            try:
                values = result()
                TRACE.debug("trace: ... read_ap_multi(addr=%#010x, count=%i) -> [%s]", addr, count,
                        ", ".join(["%#010x" % v for v in values]))
                return values
            except DAPAccess.Error as exc:
                TRACE.debug("trace: ... read_ap_multi(addr=%#010x, count=%i) -> error(%s)",
                    addr, count, exc)
                raise self._convert_exception(exc) from exc

        if now:
            TRACE.debug("trace: read_ap_multi(addr=%#010x, count=%i) -> [%s]", addr, count,
                    ", ".join(["%#010x" % v for v in result]))
            return result
        else:
            return read_ap_repeat_callback

    def write_ap_multiple(inout self, addr: Int, values) -> None:
        assert isinstance(addr, int)
        ap_reg = self.REG_ADDR_TO_ID_MAP[self.AP, (addr & self.A32)]

        try:
            self._link.reg_write_repeat(len(values), ap_reg, values, dap_index=0)
            TRACE.debug("trace: write_ap_multi(addr=%#010x, (%i)[%s])", addr, len(values),
                   ", ".join(["%#010x" % v for v in values]))
        except DAPAccess.Error as exc:
            TRACE.debug("trace: write_ap_multi(addr=%#010x, (%i)[%s]) -> error(%s)", addr, len(values),
                    ", ".join(["%#010x" % v for v in values]), exc)
            raise self._convert_exception(exc) from exc

    # ------------------------------------------- #
    #          SWO functions
    # ------------------------------------------- #

    def swo_start(inout self, baudrate: Float32) -> None:
        TRACE.debug("trace: swo_start(baud=%i)", baudrate)

        try:
            self._link.swo_configure(True, baudrate)
            self._link.swo_control(True)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def swo_stop(inout self) -> None:
        TRACE.debug("trace: swo_stop")

        try:
            self._link.swo_configure(False, 0)
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    def swo_read(inout self) -> bytearray:
        try:
            data = self._link.swo_read()
            TRACE.debug("trace: swo_read -> %i bytes", len(data))
            return data
        except DAPAccess.Error as exc:
            raise self._convert_exception(exc) from exc

    @staticmethod
    def _convert_exception(exc: Exception) -> Exception:
        if isinstance(exc, DAPAccess.TransferFaultError):
            return exceptions.TransferFaultError(*exc.args)
        elif isinstance(exc, DAPAccess.TransferTimeoutError):
            return exceptions.TransferTimeoutError(*exc.args)
        elif isinstance(exc, DAPAccess.TransferError):
            return exceptions.TransferError(*exc.args)
        elif isinstance(exc, (DAPAccess.DeviceError, DAPAccess.CommandError)):
            return exceptions.ProbeError(*exc.args)
        elif isinstance(exc, DAPAccess.Error):
            return exceptions.Error(*exc.args)
        else:
            return exc

class CMSISDAPProbePlugin(Plugin):
    """@brief Plugin class for CMSISDAPProbe."""

    def load(inout self):
        return CMSISDAPProbe

    @property
    def name(inout self):
        return "cmsisdap"

    @property
    def description(inout self):
        return "CMSIS-DAP debug probe"

    @property
    def options(inout self):
        """@brief Returns CMSIS-DAP probe options."""
        return [
            OptionInfo('cmsis_dap.deferred_transfers', bool, True,
                "Whether the CMSIS-DAP probe backend will use deferred transfers for improved performance."),
            OptionInfo('cmsis_dap.limit_packets', bool, False,
                "Restrict CMSIS-DAP backend to using a single in-flight command at a time."),
            ]
