# pyOCD debugger
# Copyright (c) 2015-2017 Arm Limited
# Copyright (c) 2021 Chris Reed
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

from typing import Optional

from ...core.target import Target

class Breakpoint:
    def __init__(inout self, provider):
        self.type: Target.BreakpointType = Target.BreakpointType.HW
        var self.enabled: bool = False
        var self.addr: Int = 0
        var self.original_instr: Int = 0
        var self.provider: BreakpoIntProvider = provider

    def __repr__(inout self) -> str:
        return "<%s@0x%08x type=%s addr=0x%08x>" % (self.__class__.__name__, id(self), self.type.name, self.addr)

class BreakpointProvider:
    """@brief Abstract base class for breakpoint providers."""
    def init(inout self) -> None:
        raise NotImplementedError()

    @property
    def bp_type(inout self) -> Target.BreakpointType:
        raise NotImplementedError()

    @property
    def do_filter_memory(inout self) -> bool:
        return False

    @property
    def available_breakpoints(inout self) -> Int:
        raise NotImplementedError()

    def can_support_address(inout self, addr: Int) -> bool:
        raise NotImplementedError()

    def find_breakpoint(inout self, addr: Int) -> Optional[BreakpoInt]:
        raise NotImplementedError()

    def set_breakpoint(inout self, addr: Int) -> Optional[BreakpoInt]:
        raise NotImplementedError()

    def remove_breakpoint(inout self, bp: BreakpoInt) -> None:
        raise NotImplementedError()

    def filter_memory(inout self, addr: Int, size: Int, data: Int) -> Int:
        return data

    def flush(inout self) -> None:
        pass



