from gmpy2 import gcd
from Crypto.Util.number import *

n1 = 22863890244905355329502218444879121992098967068885212567588832322550382269571565476722229804216790522614182986234265447480480343340056180566597327262374522569117414826955679747486113074076465468667283056121308218220999527806457552463818309423361061235047300699782063457201514653614039159966459675409621953586146091231095743649548825118937476086468617169918285492379052546748768909781454820097333293111067375755986638189670886091656813282825101928290490818507170221784980336946980401043190939317871087400436267561251842806560316003269594317264541908976843604622916612938397771819876218019609569811408087863928944739859
n2 = 25396834019528394640490541529600980922556117537438324038107125716298569990777248043066348967684236346894506759770227146549619207671751562062007330768481162637093975688682909167807919749582072320507591463121041163079102865771367435992415668638153187837308760037166747856933832106378140305308765541852838889522565034007153190524225141330109695667493844526830658201754219481830865831841336965245012965037720539791430918298660242994119733090496411675643908510757625606914559432576805118863906625455665301582481731545159511674195787561151946139919419636082690775190511208632393990834913000845076890831887255186835784042961
c1 = 2798792052596520306906487161506201765424253144083404926197470746547978562491955280164116323131693186099978677526651582130224146487924351500545757146209936518426482010371233341915851760365345316274802099517947284381607367637094400400405556888988109812081793717754725797136387614194368932966293321060057732367203512692288477818772353036431885666452035969221909268918287387499047857827190445790533284679221173200372436186499972243598616552288964557913908366130105334086059520809750893401323863112255857590960198718923416134048795210311476282103438889124183978132887302326701513155679215589455661184313859734527448361504
c2 = 11900934425575667676450495319627600558858886958379867022500122866710884877898871454939798570379571002557158224443514436359517824471900092142427117331139646250231635461356384474600784706693799046330875256351965023512944154261251426235511574316879719010312298346194007737530280411868165472424304158601012005756054876357925827274607518823449615792476822622315467435634643981046538818199679947943147388703647928775473840965549565191934261229058389441930870957306398546961351382612103093447028587644220318369842912497497694698466843444750923988948597077647164728625973186393574052980795358021421364899621646547606467631974
e = 65537

p = gcd(n1, n2)
q = n1//p
r = n2//p 

d1 = inverse(e, (p - 1)*(q - 1))
d2 = inverse(e, (p - 1)*(r - 1))

flag1 = long_to_bytes(pow(c1, d1, n1))
flag2 = long_to_bytes(pow(c2, d2, n2))
flag = flag1 + flag2

print(flag)

# FLag: WhiteHat{I_h4t3_d0g_d4y_0f_5umm3rrr}