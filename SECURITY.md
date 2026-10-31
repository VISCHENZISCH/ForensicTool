# Politique de sécurité

Forensic Analyzer lit des fichiers **hostiles par nature** (documents piégés, captures, images disque, binaires). Une faille dans un analyseur peut donc être déclenchée par une preuve.

## Signaler une vulnérabilité

N'ouvrez pas de ticket public. Écrivez à **vischenzisch@gmail.com** avec :

- la version (`./run.sh --version`, version et commit) ;
- le module concerné et un fichier de preuve qui reproduit le problème (ou sa description si le fichier est sensible) ;
- l'effet observé : exécution de code, lecture ou écriture hors du dossier de l'affaire, blocage, consommation de mémoire, rapport faux.

Accusé de réception sous 7 jours ; correctif publié avec un test de non-régression, puis mention du signalement si vous le souhaitez.

## Dans le périmètre

- Exécution de code ou de commande à partir d'une preuve.
- Écriture en dehors du dossier d'affaire (`export/`), notamment par une archive extraite.
- Blocage ou explosion mémoire sur un petit fichier (coût non linéaire).
- Rapport faux : preuve déclarée intacte ou saine alors qu'elle n'a pas été vérifiée ou analysée.
- Injection dans les rapports HTML, CSV (formules) ou dans le terminal.
- Donnée d'enquête envoyée à un tiers sans `--online`.

## Recommandations d'usage

Machine d'analyse isolée du réseau, preuves montées en lecture seule, limites de ressources (`ulimit`, `timeout`). L'outil sert au tri : ses conclusions se vérifient avant d'être présentées comme preuve.
