from Crypto.Util.number import *

pubkey = (1118073551150541760383506765868334289095849217207383428775992128374826037924363098550311115755885268424829560194236035782255428423619054826556807583363177501160213010458887123857150164238253637312857212126083296001975671629067724687807682085295986049189947830021121209617616433866087257702543240938795900959368763108186758449391390546819577861156371516299606594152091361928029030465815445679749601118940372981318726596366101388122993777320367839724909505255914071, 31678428119854378475039974072165136708037257624045332601158556362844808093636775192373992510841508137996049429030654845564354209680913299308777477807442821)
enc = 8218052282226011897229703907763521214054254785275511886476861328067117492183790700782505297513098158712472588720489709882417825444704582655690684754154241671286925464578318013917918101067812646322286246947457171618728341255012035871158497984838460855373774074443992317662217415756100649174050915168424995132578902663081333332801110559150194633626102240977726402690504746072115659275869737559251377608054255462124427296423897051386235407536790844019875359350402011464166599355173568372087784974017638074052120442860329810932290582796092736141970287892079554841717950791910180281001178448060567492540466675577782909214

flag = long_to_bytes(pow(enc, inverse(0x10001, pubkey[1] - 1), pubkey[1]))
print(flag)

# CCTF{tH3_thr3E_r4V3n5_ThRe3_cR0w5}