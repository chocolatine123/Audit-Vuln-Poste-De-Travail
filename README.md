# Audit des vulnérabilités d'un poste de travail
Audit des vulnérabilités d'un poste de travail pouvant mener à une privesc locale :
 - Recherche des mots de passe en clair (fichiers, clés de registres...) ;
 - Recherche des potentielles DLL Hijacking ;
 - Recherche des Unquoted Services Path ;
 - Recherche des mdp dans les fichiers Unattend.xml ;
 - Check de Always Install Elevated ;
 - Check des ACLs dangeureuses (pas au point ! :( ) ;
 - Check des CVE (si Nmap est présent) ;
 - Check de vulnérabilité à PrintNightmare ;
 - check des tâches plannifiées vulnérables ;
 - Utilisation de providers vulnérables (Wdigest) ;
 - Vulnérabilité GPPPasword.

Le tout rendu dans un rapport HTML, présent sur le bureau de l'utilisateur courant.
