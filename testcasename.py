import re

p=re.compile(r'(?!((^(con)$)|^(con)\..*|(^(prn)$)|^\..*|^\.\..*|^(prn)\..*|(^(aux)$)|^(aux)\..*|(^(nul)$)|^(nul)\..*|(^(com)[1-9]$)|^(com)[1-9]\..*|(^(lpt)[1-9]$)|^(lpt)[1-9]\..*)|^\s+|.*\s$)(^[^\\\/\:\*\\&?\"\<\>\|]{1,255}$)')
if(p.match('..asd')):
    print('yes')
else:
    print('no')
