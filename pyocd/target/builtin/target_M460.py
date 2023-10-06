# pyOCD debugger
# Copyright (c) 2022 Nuvoton
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

from ...coresight.coresight_target import CoreSightTarget
from ...core.memory_map import (FlashRegion, RamRegion, MemoryMap)
from ...debug.svd.loader import SVDFile

FLASH_ALGO = {
    'load_address' : 0x20000000,
    'instructions': [
    0xE00ABE00, 0x062D780D, 0x24084068, 0xD3000040, 0x1E644058, 0x1C49D1FA, 0x2A001E52, 0x4770D1F2,
    0x4770ba40, 0x4770bac0, 0x2000b5fe, 0x21009002, 0x680048fc, 0x0d000400, 0x26619002, 0x98020176,
    0xd10a42b0, 0x6bc048f8, 0x42b04ef8, 0x0780d101, 0x2005e001, 0x46010700, 0x4ef5e00e, 0x42b09802,
    0x0701d101, 0x2669e008, 0x98020176, 0xd10142b0, 0xe0010641, 0xbdfe2001, 0x2001460a, 0x180b0700,
    0x34ff1dcc, 0x462034fa, 0x07362601, 0x20031985, 0x18080380, 0x20039001, 0x18080380, 0x90001980,
    0x40304678, 0xd0012800, 0xe0004618, 0x30ff4610, 0x68003001, 0x0fc007c0, 0xd1372800, 0x26014678,
    0x40300736, 0xd0012800, 0xe0004618, 0x26594610, 0x300130ff, 0x46786006, 0x07362601, 0x28004030,
    0x4618d001, 0x4610e000, 0x30ff2616, 0x60063001, 0x26014678, 0x40300736, 0xd0012800, 0xe0004618,
    0x26884610, 0x300130ff, 0x46786006, 0x40300676, 0xd0012800, 0xe0004618, 0x30ff4610, 0x68003001,
    0x0fc007c0, 0xd1012800, 0xe7a42001, 0x2701467e, 0x403e073f, 0xd0012e00, 0xe000462e, 0x46304626,
    0x27046836, 0x6006433e, 0x06bf467e, 0x2e00403e, 0x462ed001, 0x4626e000, 0x68761d30, 0x433e2704,
    0xbf006006, 0x26014678, 0x40300736, 0xd0012800, 0xe0004628, 0x6d004620, 0x40302610, 0xd0f12800,
    0x2701467e, 0x403e073f, 0xd0012e00, 0xe0009e00, 0x46309e01, 0x272d6836, 0x6006433e, 0x26014678,
    0x40300736, 0xd0012800, 0xe0009800, 0x68009801, 0x0fc007c0, 0xd1012800, 0xe75c2001, 0xe75a2000,
    0x4605b578, 0x90002000, 0x48962100, 0x04006800, 0x90000d00, 0x01642461, 0x42a09800, 0x4892d10a,
    0x4c926bc0, 0xd10142a0, 0xe0010780, 0x07002005, 0xe00e4601, 0x98004c8e, 0xd10142a0, 0xe0080701,
    0x01642469, 0x42a09800, 0x0641d101, 0x2001e001, 0x2003bd78, 0x180a0380, 0x24011808, 0x19030724,
    0x2601467c, 0x40340736, 0xd0012c00, 0xe000461c, 0x46204614, 0x08646824, 0x60040064, 0xe7e72000,
    0x4601b5f8, 0x20002300, 0x22009000, 0x68004875, 0x0d000400, 0x26619000, 0x98000176, 0xd10a42b0,
    0x6bc04871, 0x42b04e71, 0x0780d101, 0x2005e001, 0x46020700, 0x4e6ee00e, 0x42b09800, 0x0702d101,
    0x2669e008, 0x98000176, 0xd10142b0, 0xe0010642, 0xbdf82001, 0x03802003, 0x18101814, 0x07362601,
    0x46081985, 0x460143b0, 0x0500200f, 0x11f64008, 0xd10042b0, 0x467e2301, 0x073f2701, 0x2e00403e,
    0x462ed001, 0x4626e000, 0x68364630, 0x433e2740, 0x46786006, 0x403005be, 0xd0012800, 0xe0004628,
    0x26224620, 0x467860c6, 0x403006f6, 0xd0012800, 0xe0004628, 0x60414620, 0xd10c2b00, 0x26014678,
    0x40300736, 0xd0012800, 0xe0004628, 0x26004620, 0x608643f6, 0x4678e00a, 0x07362601, 0x28004030,
    0x4628d001, 0x4620e000, 0x60864e42, 0x26014678, 0x40300736, 0xd0012800, 0xe0004628, 0x26014620,
    0xf3bf6106, 0xbf008f6f, 0x26014678, 0x40300736, 0xd0012800, 0xe0004628, 0x69004620, 0x0fc007c0,
    0xd1f12800, 0x26014678, 0x40300736, 0xd0012800, 0xe0004628, 0x68004620, 0x40302640, 0xd00f2800,
    0x2701467e, 0x403e073f, 0xd0012e00, 0xe000462e, 0x46304626, 0x27406836, 0x6006433e, 0xe7782001,
    0xe7762000, 0x4603b5fc, 0x90012000, 0x481d2400, 0x04006800, 0x90010d00, 0x01762661, 0x42b09801,
    0x4819d10a, 0x4e196bc0, 0xd10142b0, 0xe0010780, 0x07002005, 0xe00e4604, 0x98014e15, 0xd10142b0,
    0xe0080704, 0x01762669, 0x42b09801, 0x0644d101, 0x2001e001, 0x2003bdfc, 0x18250380, 0x26011820,
    0x19800736, 0x1cc89000, 0x00890881, 0x43b04618, 0x467e4603, 0x073f2701, 0x2e00403e, 0x9e00d00c,
    0x0000e00b, 0xe000ed00, 0x40003fc0, 0x20171011, 0x00000c24, 0x0055aa03, 0x4630462e, 0x27406836,
    0x6006433e, 0x05be4678, 0x28004030, 0x9800d001, 0x4628e000, 0x60c62621, 0x4678e051, 0x07362601,
    0x28004030, 0x9800d001, 0x4628e000, 0x46786043, 0x07362601, 0x28004030, 0x9800d001, 0x4628e000,
    0x60866816, 0x26014678, 0x40300736, 0xd0012800, 0xe0009800, 0x26014628, 0xf3bf6106, 0xbf008f6f,
    0x26014678, 0x40300736, 0xd0012800, 0xe0009800, 0x69004628, 0x0fc007c0, 0xd1f12800, 0x26014678,
    0x40300736, 0xd0012800, 0xe0009800, 0x68004628, 0x40302640, 0xd00f2800, 0x2701467e, 0x403e073f,
    0xd0012e00, 0xe0009e00, 0x4630462e, 0x27406836, 0x6006433e, 0xe77d2001, 0x1d121d1b, 0x29001f09,
    0x2000d1ab, 0xb5fce776, 0x20004603, 0x24009001, 0x68004852, 0x0d000400, 0x26619001, 0x98010176,
    0xd10a42b0, 0x6bc0484e, 0x42b04e4e, 0x0780d101, 0x2005e001, 0x46040700, 0x4e4be00e, 0x42b09801,
    0x0704d101, 0x2669e008, 0x98010176, 0xd10142b0, 0xe0010644, 0xbdfc2001, 0x03802003, 0x18201825,
    0x07362601, 0x90001980, 0x08811cc8, 0x46180089, 0x460343b0, 0x2701467e, 0x403e073f, 0xd0012e00,
    0xe0009e00, 0x4630462e, 0x27406836, 0x6006433e, 0x05be4678, 0x28004030, 0x9800d001, 0x4628e000,
    0x60c62600, 0x4678e055, 0x07362601, 0x28004030, 0x9800d001, 0x4628e000, 0x46786043, 0x07362601,
    0x28004030, 0x9800d001, 0x4628e000, 0x61062601, 0x8f6ff3bf, 0x4678bf00, 0x07362601, 0x28004030,
    0x9800d001, 0x4628e000, 0x07c06900, 0x28000fc0, 0x4678d1f1, 0x07362601, 0x28004030, 0x9800d001,
    0x4628e000, 0x26406800, 0x28004030, 0x467ed00f, 0x073f2701, 0x2e00403e, 0x9e00d001, 0x462ee000,
    0x68364630, 0x433e2740, 0x20016006, 0x4678e793, 0x07362601, 0x28004030, 0x9800d001, 0x4628e000,
    0x68166880, 0xd00142b0, 0xe7842001, 0x1d121d1b, 0x29001f09, 0x2000d1a7, 0x0000e77d, 0xe000ed00,
    0x40003fc0, 0x20171011, 0x00000c24, 0x00000000
    ],

    # Relative function addresses
    'pc_init': 0x20000029,
    'pc_unInit': 0x200001c1,
    'pc_program_page': 0x200003a5,
    'pc_erase_sector': 0x20000241,
    'pc_eraseAll': 0x0,

    'static_base' : 0x20000000 + 0x00000020 + 0x0000064c,
    'begin_stack' : 0x20000900,
    'begin_data' : 0x20000000 + 0x1000,
    'page_size' : 0x1000,
    'analyzer_supported' : False,
    'analyzer_address' : 0x00000000,
    'page_buffers' : [0x20001000, 0x20002000],   # Enable double buffering
    'min_program_length' : 0x1000,
}

class M467HJHAE(CoreSightTarget):
    VENDOR = "Nuvoton"

    MEMORY_MAP = MemoryMap(
        FlashRegion( start=0x00000000, length=0x100000, sector_size=0x1000,
                                                        page_size=0x1000,
                                                        is_boot_memory=True,
                                                        algo=FLASH_ALGO),
        FlashRegion( start=0x0F100000, length=0x2000,   sector_size=0x1000,
                                                        page_size=0x1000,
                                                        algo=FLASH_ALGO),
        RamRegion(   start=0x20000000, length=0x80000)
        )

    def __init__(inout self, session):
        super(M467HJHAE, self).__init__(session, self.MEMORY_MAP)
        self._svd_location = SVDFile.from_builtin("M460_v1.svd")
