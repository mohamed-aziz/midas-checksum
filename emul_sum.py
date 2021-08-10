from unicorn import *
from unicorn.x86_const import *

import struct
import binascii
class checkSum(object):
    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.code_0 = binascii.unhexlify('5589e557565383ec148b450c25ffff7f008945e88b451083e0008945ec8b450c8b551089c189d30facd917c1fb1789c825ff0f00008945e089da83e2008955e48b45e08b55e48945e08955e4b94f0700008b45e0f7e189c389d66b7de00089f101f96945e44f07000001c189ce8b45e831d88b55ec31f28945e88955ec8b450c8b551089c189d389d989cbc1fb1fc1f90389ca81e2ff0700008955e089d883e0008945e48b45e08b55e48945e08955e4b9bd0d00008b45e0f7e189c389d66b7de00089f101f96945e4bd0d000001c189ce8b45e831d88b55ec31f28945e88955ec8b450c8b551089c189d389d989cbc1fb1fc1f90e89ca81e2ff0300008955e089d883e0008945e48b45e08b55e48945e08955e4b9850900008b45e0f7e189c389d66b7de00089f101f96945e48509000001c189ce8b45e831d88b55ec31f28945e88955ec8b45e825ffff7f008b55ec83e2008945e88955ec8b45e883c4145b5e5f5dc3') 
        self.data_0 = binascii.unhexlify('38b0070800000000000000008e4816188649161846471618b64716180e471618864916186e4916181e49161896491618be4816180e481618be48161836491618764816186e48161876491618b6491618f64716180e4916183e481618664a1618ae491618c64a16188e4916189648161856481618ce4816187e491618164b16183e4b1618164a1618564a1618b64916185e4a1618e64a1618fe4a1618064a1618e6491618c6491618be4b1618ae4b1618664b16184e491618fe491618fe4b16187e4a1618de491618ee4a16183e4b1618b6491618664a1618364a1618464c1618ce4b1618be4a1618b64b1618fe4a1618764b1618964c16188e4c16182e4c1618ae4b1618fe4a1618f64b1618ee4a1618364c1618764b16182e4d1618fe4b16180e4d1618764c1618664c1618d64c1618064c1618e64d1618664b16185e4c1618664b16187e4b1618ae4b1618de4b1618b64d16180e4e1618064d1618264e1618d64b16189e4c1618064e1618de4e16182e4e1618964c1618864c1618de4e1618') 
        self.mu.mem_map(0x806f000,0x4000)
        self.mu.mem_map(0x807b000,0x4000)
        self.mu.mem_map(0x7ffff000,0x200000)
        self.mu.mem_write(0x807b124, self.data_0)
        self.mu.mem_write(0x806f6c2, self.code_0)

    def _start_unicorn(self, startaddr):
        try:
            self.mu.emu_start(startaddr, 0)
        except Exception as e:
            if self.mu.reg_read(UC_X86_REG_EIP) == 1:
                return
            else:
                print ('[!] Exception occured - Emulator state (x86):')
                print ("UC_X86_REG_EAX : %08X" % (self.mu.reg_read(UC_X86_REG_EAX)))
                print ("UC_X86_REG_EBP : %08X" % (self.mu.reg_read(UC_X86_REG_EBP)))
                print ("UC_X86_REG_EBX : %08X" % (self.mu.reg_read(UC_X86_REG_EBX)))
                print ("UC_X86_REG_ECX : %08X" % (self.mu.reg_read(UC_X86_REG_ECX)))
                print ("UC_X86_REG_EDI : %08X" % (self.mu.reg_read(UC_X86_REG_EDI)))
                print ("UC_X86_REG_EDX : %08X" % (self.mu.reg_read(UC_X86_REG_EDX)))
                print ("UC_X86_REG_ESI : %08X" % (self.mu.reg_read(UC_X86_REG_ESI)))
                print ("UC_X86_REG_ESP : %08X" % (self.mu.reg_read(UC_X86_REG_ESP)))
                print ("UC_X86_REG_EIP : %08X" % (self.mu.reg_read(UC_X86_REG_EIP)))
                raise e


    def run(self, arg_0):

        self.mu.reg_write(UC_X86_REG_ESP, 0x7fffff00)
        self.mu.mem_write(0x7fffff00, b'\x01\x00\x00\x00')
        self.mu.mem_write(self.mu.reg_read(UC_X86_REG_ESP) + 0x8, struct.pack('<Q', arg_0))
        #self.mu.mem_write(self.mu.reg_read(UC_X86_REG_ESP) + 0xc, struct.pack('<I', arg_1))

        #self.mu.reg_write(UC_X86_REG_EBP, 0x7fffff00)
        self._start_unicorn(0x806f6c2)
        return self.mu.reg_read(UC_X86_REG_EAX)


x = checkSum()
#print (x.run(18323065256474977))

code = int("".join(input("Enter the number in form xxx-xxxx-xxx-xxxx-xxx: ").split("-")))
out = x.run(code)

print("""Enter which machine to license to:
  [1] Pro3
  [2] Pro6
  [3] Pro9
  [4] XL8
  [5] DL2""")

choice = int(input("?: "))

checksums = {
    1: 0x328d1, # PRO3
    2: 0xa7089, # PRO6
    3: 0x479de, # PRO9
    4: 0x32c0d, # XL8
    5: 0x8dde4, # DL2
}

k = checksums[choice]

outcode = str(out ^ k).zfill(7)

print("[*] Your code is {}-{}".format(outcode[:3], outcode[3:]))
