# SLH_Labo2
## Questions

> 1. Les passkeys, comme l’authentification unique (SSO), permettent toutes deux à un utilisateur d’utiliser un seul mécanisme de sécurité pour tous ses services, sans s’exposer à une attaque de "credentials stuffing". Mais quelle est la différence en termes de risque ?

Les passkeys sont des clés cryptographiques uniques générées pour chaque service, ce qui signifie qu'une compromission d'un service n'affecte pas les autres, chaque passkey est indépendante. 
Au contraire, l'authentification unique (SSO) centralise l'accès à plusieurs services via un seul point de connexion. Si ce point est compromis, par exemple si notre compte Google se fait hacker, tous les services associés sont à risque, c'est malheureusement un modèle du type "single point of failure". 

Donc au final, les passkeys offrent une meilleure isolation des risques par rapport au SSO.


> 2. Concernant la validation d’entrées pour les images, quelles sont les étapes que vous avez effectuées ? Et comment stockez-vous les images ?

Pour la validation des images, les étapes suivantes ont été effectuées :  
- Vérification du format de l'image pour s'assurer qu'il s'agit d'un fichier JPEG.
- Vérification de la taille de l'image pour s'assurer qu'elle ne dépasse pas la taille maximale autorisée pour éviter les attaques de type "denial of service".
- Vérification du contenu de l'image pour s'assurer qu'il s'agit bien d'une image JPEG valide.

- Stockage des images dans le répertoire spécifié par consts::UPLOADS_DIR.

Les images sont stockées en créant un fichier dans le répertoire ./data/uploads avec le nom de fichier fourni.

> 3. Que pensez-vous de la politique de choix des noms de fichiers uploadés ? Y voyez-vous une vulnérabilité ? Si oui, suggérez une correction.

La politique actuelle de choix des noms de fichiers uploadés utilise le nom de fichier fourni par l'utilisateur, ce qui peut entraîner des vulnérabilités telles que des collisions de noms de fichiers ou des attaques de type "path traversal". Pour corriger cela, il faudrait générer un nom de fichier unique pour chaque fichier uploadé, par exemple en utilisant une fonction de hachage sur le contenu du fichier.

```rust
let filename = format!("{}.jpg", Uuid::new_v4());
```
Chaque fichier uploadé serait alors stocké sous un nom unique généré aléatoirement donc pas de risque de collision.