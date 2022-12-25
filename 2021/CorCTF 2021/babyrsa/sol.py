from coppersmith import * # https://github.com/defund/coppersmith/blob/master/coppersmith.sage
from Crypto.Util.number import *

n = 73542616560647877565544036788738025202939381425158737721544398356851787401183516163221837013929559568993844046804187977705376289108065126883603562904941748653607836358267359664041064708762154474786168204628181667371305788303624396903323216279110685399145476916585122917284319282272004045859138239853037072761
e = 65537
ct = 2657054880167593054409755786316190176139048369036893368834913798649283717358246457720021168590230987384201961744917278479195838455294205306264398417522071058105245210332964380113841646083317786151272874874267948107036095666198197073147087762030842808562672646078089825632314457231611278451324232095496184838

p_h = 108294440701045353595867242719660522374526250640690193563048263854806748525172379331
p_l = 341078269246532299656864881223

q_h = 679098724593514422867704492870375465007225641192338424726642090768164214390632598250
q_l = 39563231146143146482074105407

k = 41
x = len(str(p_l))
y = len(str(q_l))

# p = p_h*10**(x + 41) + _p*10**x + p_l
# q = p_h*10**(y + 41) + _q*10**y + q_l

pol = PolynomialRing(Zmod(n), "p, q"); p, q = pol.gens()
f = (p_h*10**(x + k) + p*10**x + p_l)*(q_h*10**(y + k) + q*10**y + q_l)
bounds = (10**41, 10**41)

_p, _q = small_roots(f, bounds, 1, 3)[0]
p, q = ZZ(p_h*10**(x + k) + _p*10**x + p_l), ZZ(q_h*10**(y + k) + _q*10**y + q_l)
d = inverse(e, (p - 1)*(q - 1))
flag = long_to_bytes(ZZ(pow(ct, d, n)))

print(flag)