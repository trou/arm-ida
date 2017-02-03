from ida_search import find_text
from idc import MinEA
import re

regex = re.compile("m(rc|cr).*p15,(.*), *(r\d+|sp), *c(\d+), *c(\d+), *(\d+)", re.IGNORECASE)

C0 = {0: {0: "read ID code", 1: "read cache type"}}
C1 = {0: {0: "read control register"}}
C2 = {0: {0: "read TTBR"}}
C5 = {0: {0: "Data fault status"}}
C6 = {0: {0: "fault address"}}
#C7 = {2: {5: ""}
p15_read = {0: C0, 1:C1, 2:C2, 5:C5, 6:C6}

C1_w = { 0: {0: "write control register"}}
C2_w = { 0: {0: "write TTBR"}}
C3_w = { 0: {0: "write domain access permissions"}}
C7_w = { 2: {5: "allocate d-cache line"},

         5: {1: "Invalidate ICache single entry (MVA)",
             6: "Flush Branch Target Cache Entry Register"},
         7: {0: "VA to PA with privileged write permission check Register"},
         6: {1: "Invalidate DCache single entry (MVA)"},
        10: {1: "Clean DCache single entry (MVA)", 
             4: "Drain write buffer"}}

C8_w = { 5: {1: "Invalidate Instruction TLB Single Entry Register"}, 
         6: {1: "Invalidate Data TLB Single Entry Register"},
         7: {0: "Invalidate Unified TLB Register"}}
p15_write = {1:C1_w, 2:C2_w, 3:C3_w, 7:C7_w, 8:C8_w}

def p15_read_to_human(num, reg, c1, c2, cst):
    if c1 < 0 or c1 > 15:
        return None
    try:
        return p15_read[c1][c2][cst]
    except KeyError:
        return None
       
def p15_write_to_human(num, reg, c1, c2, cst):
    if c1 < 0 or c1 > 15:
        return None
    try:
        return p15_write[c1][c2][cst]
    except KeyError:
        return None


ea = MinEA()
while True:
    ea = find_text(ea, 0, 0, "m(rc|cr).*p15,.*,.*,.*,.*", SEARCH_DOWN|SEARCH_REGEX)
    if ea == BADADDR:
        break
    disass = GetDisasm(ea).lower()
    m = regex.match(disass)
    if m is None:
        print "regex error : "+disass
        ea += 4
        continue
    clean = map(lambda x:x.strip(), m.groups())
    rw, num, reg, c1, c2, cst = clean
    if reg == "sp":
        reg = "13"
    else:
        reg = reg[1:]
    if rw == 'cr':
        human = p15_write_to_human(num, int(reg), int(c1), int(c2), int(cst))
    else:
        human = p15_read_to_human(num, int(reg), int(c1), int(c2), int(cst))
    if human:
        MakeComm(ea, human)
    else:
        print "%08x: %s %s r%s c%s c%s %s is unknown" % (ea, rw, num, reg, c1, c2, cst)
    ea += 4
