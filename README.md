# Retour sur le challenge Cybersec organisé par la DGSE

Lien : [Challenge Richelieu](https://www.challengecybersec.fr/).
Le site d'origine n'étant plus actif, voici le [PDF](Richelieu.pdf) permettant de faire la majorité du challenge.

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
 - il semble aussi possible de récupérer ce lien via une recherche google, le fichier étant indexé : `site:www.challengecybersec.fr`

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
 
### Image

Une fois cette clé obtenue, il est simple de déchiffrer la clé GPG puis l'image du dossier :

```bash
openssl rsautl -decrypt -inkey recovered.key -out motDePasseGPG.txt -in motDePasseGPG.txt.enc
gpg --symmetric --decrypt lsb_RGB.png.enc -o lsb_RGB.png
```

Le nom de l'image mettant la puce à l'oreille, il faut alors extraire les bits de poids faible (lsb) de ce fichier :

```python
#coding: utf-8
import base64
from PIL import Image
import array

image = Image.open("lsb_RGB.png")

extracted = ''

pixels = image.load()
for x in range(0,image.width):
	for y in range(0,image.height):
		r,g,b = pixels[x,y]
		extracted += bin(r)[-1]
		extracted += bin(g)[-1]
		extracted += bin(b)[-1]

print(len(extracted)/8)
data = array.array('B')
for i in range(len(extracted)//8):
	byte = extracted[i*8:(i+1)*8]
	data.append(int(byte, 2))

f=open("out.png", "wb")
data.tofile(f)
```

Le fichier obtenu débute par une représentation textuelle d'un fichier binaire (comme obtenue avec `xxd`). Il suffit alors d'en supprimer la fin et de l'extraire avec `xxd -r out.png > out2`.

Sources :
 - je me suis inspiré du code présent sur [boitaklou.fr](https://www.boiteaklou.fr/Steganography-Least-Significant-Bit.html#python-my-love) pour réaliser mon script python

Notes :
 - j'ai cru pendant quelques temps faire fausse route car j'avais parcouru mon fichier en lignes/colonnes au lieu de colonnes/lignes...

### UPX

En inspectant le fichier obtenu, je repère très vite le texte suivant :

```
$Info: This file is packed with the ALD executable packer http://upx.sf.net $
$Id: ALD 3.91 Copyright (C) 1996-2013 the ALD Team. All Rights Reserved. $
```

Je cherche donc à "extraire" le fichier d'origine, mais j'obtiens le message d'erreur suivant :

```
upx: upx.txt: NotPackedException: not packed by UPX
```

Un [résultat de recherche](https://reverseengineering.stackexchange.com/questions/3335/decoding-the-upx-elf-header-file) m'apprend qu'il est fréquent de remplacer les occurences d'UPX! dans les fichiers UPX. Le message sur l'équipe ALD devient plus clair.

Je remplace donc `ALD` par `UPX` dans mon fichier, mais j'obtiens l'erreur suivante :

```
upx: upx.txt: CantUnpackException: header corrupted 3
```

J'ai fini par réussir à obtenir le message `Unpacked 1 file.` en commençant par remplacer `41 4c 44` par `55 50 58` avant d'appliquer `xxd -r`.

Notes :
 - j'aurais pu éxécuter les fichier plus tôt, mais j'ai naîvement pensé qu'UPX servait à chiffrer le fichier
 - je ne comprends toujours pas pourquoi pourquoi l'erreur `header corrupted 3` se produit.

### ELF

Le fichier exécutable obtenu produit les messages suivants :

```
usage : ./out3.txt <mot de passe>
```

```
Mauvais mot de passe
```

En utilisant les commandes file, strings et objdump comme indiqué sur ce [tuto](http://manoharvanga.com/hackme/), j'obtiens les adresses des chaînes d'erreur et de réussite du programme, ainsi que des instructions `lea` qui permettent de les lire.

La lecture de l'assembleur n'étant pas aisée, j'utilise [Ghidra](https://ghidra-sre.org/) pour le visualiser décompilé.

Aux adresses obtenues, j'obtiens le code suivant :

```c
ulong FUN_00400b20(int iParm1,undefined8 *puParm2)

{
  uint uVar1;
  ulong uVar2;
  
  if (iParm1 < 2) {
    FUN_00407840("usage : %s <mot de passe>\n",*puParm2);
    uVar2 = 2;
  }
  else {
  	//valeur testée pour afficher le message de réussite
    uVar1 = FUN_00400aae(puParm2[1]);
    uVar2 = (ulong)uVar1;
    if (uVar1 == 0) {
      FUN_00408010("Mauvais mot de passe");
    }
    else {
      FUN_00408010("Bravo ! Vous pouvez utiliser ce mot passe pour la suite ;-)");
      uVar2 = 0;
    }
  }
  return uVar2;
}
```

Je regarde donc en détail le code de la fonction `FUN_00400aae` :

```c
ulong FUN_00400aae(byte *pbParm1)

{
  int iVar1;
  undefined8 uVar2;
  ulong uVar3;
  byte bVar4;
  long lVar5;
  byte *pbVar6;
  byte bVar7;
  
  lVar5 = -1;
  pbVar6 = pbParm1;
  //boucle comptant la longeur de la chaîne entrée
  do {
    if (lVar5 == 0) break;
    lVar5 = lVar5 + -1;
    bVar4 = *pbVar6;
    pbVar6 = pbVar6 + 1;
  } while (bVar4 != 0);
  uVar2 = 0;
  //le résultat est comparé à -32
  //en comptant l'initialisation à -1 et le \0 final, on cherche une chaîne de 30 caractères
  if (lVar5 == -0x20) {
    bVar4 = *pbParm1;
    if (bVar4 != 0) {
      //adresse de la chaîne utilisée pour vérifier le mot de passe
      pbVar6 = &DAT_004898c0;
      pbParm1 = pbParm1 + 1;
      uVar3 = 1;
      //initialisation
      bVar7 = 0x33;
      //boucle de vérification de la chaîne
      do {
        iVar1 = (int)uVar3;
        uVar3 = 0;
        if (iVar1 != 0) {
          //XOR avec la valeur précédente
          uVar3 = (ulong)((bVar4 ^ bVar7) == *pbVar6);
        }
        bVar7 = *pbVar6;
        bVar4 = *pbParm1;
        pbVar6 = pbVar6 + 1;
        pbParm1 = pbParm1 + 1;
      } while (bVar4 != 0);
      return uVar3;
    }
    uVar2 = 1;
  }
  return uVar2;
}
```

Ce script m'a donc permis de truver le mot de passe correct :

```python
numbers = [
# initialisation
'33',
# 30 valeurs suivant &DAT_004898c0
...
]

for a, n in enumerate(numbers[:-1]):
	print(chr(int(n, 16) ^ int(numbers[a+1], 16)))
```

Comme l'indique le message "Bravo ! Vous pouvez utiliser ce mot passe pour la suite ;-)", le mot de passe trouvé permet de déchiffre l'archive qui était fournie avec les autres fichiers dans l'étape précédente.

Celle-ci contient un fichier texte qui donne des instructions pour se connecter en SSH à une machine distante pour la suite du challenge.

Notes :
 - cette partie m'a permis de découvrir l'utilisation de Ghidra qui est très pratique (qui m'a cependant demandé d'installer jdk >= 11)

## Wargame

Les identifiants obtenus permettent d'ouvrir une connexion qui affiche le message suivant :

```
Partie Wargame du CTF Richelieu

Outils disponibles:
*******************

  * gdb (avec peda)
  * python 2.7
  * pwnlib
  * checksec
  * vim
  * emacs
  * nano
  * ltrace
  * strace
  * ...

ATTENTION : les connexions sont coupées et les fichiers sont détruits
automatiquement au bout de 1 heure.
Pensez à sauvegarder vos fichiers sur un autre poste pour ne pas les perdre.
```


Je précise pour la suite que je connaiss très mal gdb, ltrace et strace, et que je n'ai jamais utilisé pwnlib ni checksec, la suite s'annonce difficile.

### defi1

Un `ls -l` donne les informations suivantes :

```
total 16
-r-------- 1 defi1-drapeau defi1-drapeau  133 Apr 26 14:06 drapeau.txt
-r-sr-sr-x 1 defi1-drapeau defi1-drapeau 8752 May 10 10:50 prog.bin
```

Je suppose donc qu'il faut ouvrir le fichier drapeau.txt grâce aux droits de l'éxécution de prog.bin.

Ce dernier propose un choix entre plusieurs commandes, dont l'affichage d'un train. Je repère un appel à `sl` grâce à ltrace : `system("sl"`.

En ajoutant le dossier courant au `$PATH` et en créeant un fichier exéxutable `sl` contenant `cat drapeau.txt`, j'obtiens les identifiants de l'étape suivante.

Notes :
 - j'ai perdu beaucoup de temps sur ce défi, en cherchant à comprendre comment je pourrais utiliser la mention `RELRO:    Partial RELRO` obtenue avec `checksec` alors que la solution était bien plus simple

### defi2

Le défi suivant est de la même forme. Le programme permet de vérifier si un couple login / password vérifie certaines caractéristiques. 

J'ai pu remarquer que la longueur des chaines entrées n'était pas vérifiée. J'ai donc provoqué un `buffer overflow` avec une chaîne suffisamment longue, le programme produisant ainsi une segfault.

La résolution de ce défi passait donc par l'injection de code assembleur après la fin du buffer. Quelques recherches à ce sujet m'ont amené sur ce [tuto](https://beta.hackndo.com/return-oriented-programming/), mais cela dépasse mes compétences. Je me suis donc arrêté à ce niveau du challenge.

### suite ?

Je ne sais pas combien de défis il me restait, ni si d'autres épreuves suivent encore celles-ci, mais je suis preneur de toutes informations à ce sujet.
