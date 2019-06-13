# Retour sur le challenge Cybersec organisé par la DGSE

Lien : [Challenge Richelieu](https://www.challengecybersec.fr/)
Découvert grâce à un [article de ZATAZ](https://www.zataz.com/concours-dgse-richelieu/)

Notes :
 - je reste un noob en sécurité informatique, le goût du challenge et l'envie d'en savoir plus m'ont poussé à entreprendre ce défi
 - je n'ai pas fini le défi, je suis intéressé par des infos sur la suite du challenge

## Site Web

Une inspection du code source de la page permet de découvrir ceci :

```javascript
let login = "rien";
let password = "nothing";
if (login === password) {
    document.location="./Richelieu.pdf";
}
```

Le document pdf permet d'accéder à l'étape suivante.

Notes :
 - Il semble aussi possible de récupérer ce lien via une recherche google, le fichier étant indexé : `site:www.challengecybersec.fr`

## Fichier PDF

### Contenu

Le fichier présenté contenait un petit texte sur Richelieu, puis de nombreuses pages blanches.

Une copie de son contenu permettait d'afficher des lignes invisibles car trop petites. Celles-ci décrivaient un fichier encodé en base64.

Une fois celui-ci décodé, la commande `file` permet de voir qu'il s'agit d'un fichier jpg. Une fois affiché, il s'agit d'un dessin de Richelieu.

Le décodage du fichier en console avait cependant permis d'afficher des fragments de texte, comme `Le mot de passe`, `de cette archive`, `est :`, ainsi qu'un code de la forme `DGSE{XXX}` et de nombreux noms de fichiers.

Sur les conseils d'un ami, j'ai pu extraire de ce fichier une archive zip avec l'outil `foremost`. Le fichier s'ouvre ensuite avec le mot de passe `DGSE{XXX}`.

Notes :
 - j'ai du installer un vrai lecteur PDF sur ma machine, le lecteur des navigateurs ne me permettant pas de capturer facilement l'intégralité de la page
 - une version de `foremost` pour windows est disponible sur Internet, je n'ai pas résussi à la configurer correctement pour extraire le zip
 - il était possible de repérer le fichier zip grâce à la présence de l'entête `PK`

### Archive

#### Contenu

L'archive contenait plusieurs fichiers : un historique bash, une image chiffrée symétriquement avec une clé GPG, cette clé GPG chiffrée avec une clé privée RSA, une clé publique ainsi qu'un fichier texte et une archive protégée par un mot de passe.

#### Analyse des commandes effectuées

```bash
1337  gpg -o lsb_RGB.png.enc --symmetric lsb_RGB.png
1338  vim motDePasseGPG.txt
1339  openssl genrsa -out priv.key 4096
1340  openssl rsa -pubout -out public.key -in priv.key
1341  openssl rsa -noout -text -in priv.key | grep prime1 -A 18 > prime.txt
1342  sed -i 's/7f/fb/g' prime.txt
1343  sed -i 's/e1/66/g' prime.txt
1344  sed -i 's/f4/12/g' prime.txt
1345  sed -i 's/16/54/g' prime.txt
1346  sed -i 's/a4/57/g' prime.txt
1347  sed -i 's/b5/cd/g' prime.txt
1348  openssl rsautl -encrypt -pubin -inkey public.key -in motDePasseGPG.txt -out motDePasseGPG.txt.enc
```

Le fichier permet de comprendre comment ont été générés les différents fichiers présents dans l'archive.

La première étape va donc être de restaurer la clé privée utilisée.

#### Clé privée

Il fallait tout d'abord extraire les informations provenant de la clé publique avec :

```bash
openssl rsa -noout -text -pubin -in  public.key
```

Il s'agissait ensuite d'annuler les différents remplacements effectués avec `sed`, puis de générer une clé privée au bon format. J'ai pour cela utilisé ce script :

```python
import itertools
import re

# lecture des fichiers ne contenant plus que les codes hexadecimaux extraits de prime.txt et de la clé publique
f = open("prime1.txt", "r")
prime1 = f.readline()
f = open("modulus.txt", "r")
modulus = f.readline()

# remplacement à effectuer, j'en ai supprimé un car son résultat n'apparaît pas dans le code hexadécimal
sed = [
	('7f','fb'), 
	('f4','12'), 
	('16','54'), 
	('a4','57'), 
	('b5','cd')
]

modulus = int(modulus.replace(":", ""), 16)

# extraction de tous les remplacements pouvant être effectués, A->B et BB en résultat pouvant provenir de AA, AB, BA ou BB
replacements = []
for s in sed:
	for x in re.finditer(s[1], prime1):
		replacements.append((s[0], x.start(), x.end()))

# parcours de toutes les solutions possibles
for choice in itertools.product(*([[True, False]] * len(replacements))):
	current_line = prime1
	for i_rep, rep in enumerate(replacements):
		if choice[i_rep]:
			current_line = current_line[:rep[1]] + rep[0] + current_line[rep[2]:]
	current_line = int(current_line.replace(":", ""), 16)
	# on cherche prime1 et prime2 tels que modulus=prime1*prime2
	if (modulus % current_line)==0:
		# changement de notation car la suite du code n'est pas de moi :)
		p = current_line
		q = modulus//current_line

n = modulus
e = 0x10001
phi = (p -1)*(q-1)
def xgcd(a, b):
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def modinv(a, b):
    g, x, _ = xgcd(a, b)
    if g == 1:
        return x % b

d = modinv(e,phi)
dp = modinv(e,(p-1))
dq = modinv(e,(q-1))
qi = modinv(q,p)

import pyasn1.codec.der.encoder
import pyasn1.type.univ
import base64
def pempriv(n, e, d, p, q, dP, dQ, qInv):
    template = '-----BEGIN RSA PRIVATE KEY-----\n{}-----END RSA PRIVATE KEY-----\n'
    seq = pyasn1.type.univ.Sequence()
    for x in [0, n, e, d, p, q, dP, dQ, qInv]:
        seq.setComponentByPosition(len(seq), pyasn1.type.univ.Integer(x))
    der = pyasn1.codec.der.encoder.encode(seq)
    return template.format(base64.encodestring(der).decode('ascii'))

key = pempriv(n,e,d,p,q,dp,dq,qi)
key
'-----BEGIN RSA PRIVATE KEY-----\nMGMCAQACEQDICCEgY36GKnn7Zx8E6qJlAgMBAAECEH+rmKEYf7fXIPGHhsXaDj0CCQDzgJALl2VQ\n7wIJANJMZcP2HhnrAgkAvnmFtBuEfG8CCBjtJULM8VRxAgkA7M4iNPZ4lKs=\n-----END RSA PRIVATE KEY-----\n'
f = open("recovered.key","w")
f.write(key)
f.close()
```

Notes :
 - ma première version de script remplaçait toutes les occurences des chaînes de `sed`, la solution n'était pas un diviseur de modulus
 - la version recursive d'egcd saturait la pile, j'ai donc cherché un équivalent itératif (mais il semble qu'elle soit corrigée un peu plus bas dans ma source)

Sources :
 - pour générer la clé privée une fois prime1 restauré : [0day.work](https://0day.work/how-i-recovered-your-private-key-or-why-small-keys-are-bad/)
 - pour rendre egcd itératif [Wikibooks](https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm)
