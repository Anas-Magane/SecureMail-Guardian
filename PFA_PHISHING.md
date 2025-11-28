# SecureMail Guardian : Plateforme de Détection des Cybermenaces Email par Analyse DFIR et Threat Intelligence

## Analyse des Besoins
*Exigences Non-Fonctionnelles*

```bash
	Dashboard UI/UX user-friendly --> Interface simple et intuitive
	Security --> Pas de stockage des emails sensibles
	Performance --> Analyse rapide < 5 secondes
```
*Exigences Fonctionnelles*

```bash
	Détection phishing via 3 techniques DFIR minimum
	Génération de rapport avec pourcentage de confiance
	Scan des fichiers .eml + calcul hash + intégration VirusTotal
```

## Conception 
*Architecture Globale du Flux*

```bash
	[INPUT] --> [PROCESSING] → [ANALYSIS] → [REPORTING] → [OUTPUT]
```

**PHASE 1: INPUT & COLLECTION**

Sources d'Entrée :

```bash
	Fichier .EML uploadé via dashboard
	Email direct via connexion IMAP
	Copier-coller du contenu email
```

Composants d'Entrée :
```bash
	Upload Handler : Gestion des fichiers .eml
	Email Parser : Extraction des composants email
	Pre-validator : Vérification format fichier
```

**PHASE 2: PROCESSING & EXTRACTION**

2.1 Décomposition de l'Email
```bash
			Email Input
			    │
			    ├──  METADONNEES
			    │   ├── Headers (From, To, Subject, Date)
			    │   ├── En-têtes techniques (Received, SPF, DKIM)
			    │   └── Informations routage
			    │
			    ├──  CONTENU TEXTUEL
			    │   ├── Corps du message (plain text)
			    │   ├── Corps HTML (si existant)
			    │   └── Encodages et caractères
			    │
			    ├──  LIENS & URLS
			    │   ├── URLs dans le corps
			    │   ├── Liens d\'images
			    │   └── Redirections
			    │
			    └──  PIÈCES JOINTES
			        ├── Fichiers attachés
			        ├── Images intégrées
			        └── Metadata fichiers
```

2.2 Normalisation des Données
```bash
	Conversion encodages
	Nettoyage HTML
	Extraction URLs absolues
	Calcul hash des fichiers
```
**PHASE 3: ANALYSIS DFIR (3 TECHNIQUES)**

***TECHNIQUE DFIR #1: FORENSIC HEADER ANALYSIS***

### Composants Analysés :
	Chaîne Received : Analyse des sauts et IPs
	Authentification : SPF, DKIM, DMARC
	En-têtes techniques : Message-ID, Return-Path
	Incohérences : Dates, timezones

### Indicateurs de Menace :SPF = fail ou softfail
	DKIM manquant ou invalide
	Différence From/Return-Path
	IPs de pays à risque
	Headers manquants ou modifiés

***TECHNIQUE DFIR #2: CONTENT & BEHAVIORAL ANALYSIS***

### Analyse Lexicale :
	Mots-clés phishing (urgent, vérification, mot de passe)
	Ton impersonnel vs ton personnalisé
	Erreurs grammaticales intentionnelles
	Marques impersonnelles ("Chère cliente")

### Analyse Structurelle :
	Présence formulaires de login
	Liens de "désabonnement" suspects
	Menaces ou sentiment d'urgence
	Demandes d'actions immédiates

### URL & Link Analysis :
	Domaines suspects (.tk, .ml, .ga)
	URL shortening masqué
	IP addresses directes
	Homoglyphes (g00gle.com vs google.com)

***TECHNIQUE DFIR #3: FILE & ATTACHMENT FORENSICS***

### Analyse Fichiers :

	Signature vs Extension : mismatch détecté
	Types dangereux : .exe, .js, .vbs déguisés
	Macros dans documents Office
	Metadata révélatrice

### Intégration External :

	Calcul Hash (SHA256) des fichiers
	VirusTotal API : vérification réputation
	Sandboxing : analyse comportementale
	Blacklists : comparaison bases de données

**PHASE 4: SCORING & THREAT ASSESSMENT**

### 4.1 Système de Points
***Score de Base: 100 points (email légitime)***

*PÉNALITÉS:*
	- Header Analysis: -1 à -30 points
	- Content Analysis: -1 à -40 points  
	- File Analysis: -1 à -50 points

*BONUS:*
	- Authentification valide: +10 points
	- Expéditeur de confiance: +5 points

### 4.2 Calcul Pourcentage Confiance
	
Score Final = 100 - Σ(Pénalités) + Σ(Bonus)
Pourcentage = max(0, min(100, Score Final))

ÉCHELLES:
	90-100%  → SAFE ( Sécurisé)
	70-89%   → LOW RISK ( Faible Risque)  
	50-69%   → MEDIUM RISK ( Risque Moyen)
	30-49%   → HIGH RISK ( Risque Élevé)
	0-29%    → CRITICAL ( PHISHING DÉTECTÉ)

### 4.3 Seuils de Détection
	>90% : Email légitime
	80-90% : Suspicion faible
	70-80% : Suspicion moyenne
	50-70% : Forte suspicion
	<50% : Phishing confirmé

**PHASE 5: REPORTING & VISUALIZATION**

### 5.1 Structure du Rapport

il doit inclut ces elements comme :  

```bash
{
  "metadata_analysis": {
    "score": -25,
    "findings": ["SPF failed", "DKIM missing"]
  },
  "content_analysis": {
    "score": -35, 
    "findings": ["Urgency keywords", "Suspicious links"]
  },
  "file_analysis": {
    "score": -10,
    "findings": ["VirusTotal: 2/65 detection"]
  },
  "final_assessment": {
    "confidence_score": "70%",
    "threat_level": "MEDIUM_RISK",
    "verdict": "SUSPICIOUS_EMAIL"
  }
}
```

### 5.2 Dashboard Components

```bash
		 DASHBOARD SECUREMAIL GUARDIAN
		├──  UPLOAD ZONE
		│   └── Drag & Drop .eml files
		│
		├──  RESULTS SUMMARY  
		│   ├── Confidence Score (pourcentage gros)
		│   ├── Threat Level (couleur + icône)
		│   └── Quick Verdict (Safe/Suspicious/Phishing)
		│
		├──  DETAILED ANALYSIS
		│   ├── Header Analysis Findings
		│   ├── Content Analysis Findings  
		│   ├── File Analysis Findings
		│   └── DFIR Techniques Applied
		│
		├──  FORENSIC DATA
		│   ├── File Hashes (SHA256)
		│   ├── External Checks (VirusTotal)
		│   └── Technical Indicators
		│
		└──  ACTIONS
		    ├── Download PDF Report
		    ├── Share Analysis
		    └── New Analysis

```
**PHASE 6: OUTPUT & ACTIONS**

### Types de Sortie :
	Rapport Visual : Dashboard interactif
	Rapport PDF : Format professionnel
	Alertes : Notifications immédiates
	Logs : Audit trail complet

### Actions Utilisateur :
	Marquer comme faux-positif
	Partager l'analyse
	Exporter les données
	Archiver le rapport

# GARANTIES PERFORMANCE & SECURITY 

## Performance (< 5 secondes) :
	Parallélisation : Analyses simultanées
	Cache : Résultats VirusTotal mis en cache
	Optimisation : Algorithmes légers
	Async Processing : Non-bloquant

## Security :
	No Storage : Fichiers supprimés après analyse
	Data Minimization : Seules les métadonnées conservées
	Encryption : Données transit chiffrées
	API Security : Tokens temporaires VirusTotal

# FLUX COMPLET RÉSUMÉ

```bash
			[.EML FILE]
			    ↓
			[PARSING & EXTRACTION]
			    ↓
			[DFIR ANALYSIS PARALLEL]
			    ├── HEADER FORENSICS
			    ├── CONTENT ANALYSIS  
			    └── FILE FORENSICS
			    ↓
			[THREAT SCORING ENGINE]
			    ↓
			[CONFIDENCE CALCULATION]
			    ↓
			[REPORT GENERATION]
			    ↓
			[DASHBOARD DISPLAY + PDF]

```

