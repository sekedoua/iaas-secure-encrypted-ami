# Création et déploiement sécurisés d'AMI

Ce référentiel contient le code et les workflows nécessaires pour automatiser la création d'une image machine Amazon (AMI) sécurisée et chiffrée et la déployer en tant qu'instance EC2. Le processus garantit que l'AMI et l'instance respectent les meilleures pratiques de sécurité AWS en utilisant le chiffrement et l'accès contrôlé.

---

## **Fonctionnalités**
- **Création d'AMI chiffrée :** automatise la création d'une AMI avec chiffrement à l'aide d'AWS KMS.
- **Flux de travail GitHub Actions :** fournit un flux de travail GitHub Actions préconfiguré pour gérer et valider la création d'AMI et le déploiement d'instances.
- **Bonnes pratiques de sécurité :**
- Configure les groupes de sécurité avec un accès restreint.
- Garantit des volumes racines chiffrés pour les instances EC2.
- **Entrées personnalisables :** prend en charge les configurations définies par l'utilisateur telles que le type d'instance, l'ID AMI de base et le groupe de sécurité.

---

## ** Structure du dossier  projet **
```plaintext
.
├── .github/
│   └── workflows/
│       └── secure_ami.yml   # Flux de travail GitHub Actions pour la création d'AMI sécurisée
├── requirements.txt         # Dépendances Python pour le projet
├── secure_ami.py            # Python script to create and validate a secure AMI
├── .gitignore               # Fichiers à ignorer dans le contrôle de version
├── README.md
