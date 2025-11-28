#!/bin/bash
# ==================================================================
# Script de génération de certificats TLS pour collectd tcpsock
# ==================================================================
# Usage:
#   ./generate_tls_certs.sh                # Générer tout (CA + serveur + client)
#   ./generate_tls_certs.sh --server-only  # Générer seulement serveur
#   ./generate_tls_certs.sh --client-only  # Générer seulement client
# ==================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
TLS_DIR="/etc/collectd/tls"
COUNTRY="FR"
STATE="Pays de la Loire"
CITY="La Chevroliere"
ORG="Proginov"
CA_CN="Collectd"
SERVER_CN="progibox"
CLIENT_CN="client1"

# Validité des certificats
CA_DAYS=3650    # 10 ans
CERT_DAYS=365   # 1 an

# Parse arguments
MODE="full"
if [ "$1" = "--server-only" ]; then
    MODE="server"
elif [ "$1" = "--client-only" ]; then
    MODE="client"
elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Usage: $0 [--server-only|--client-only|--help]"
    echo ""
    echo "Options:"
    echo "  (none)          Generate CA + server + client certificates"
    echo "  --server-only   Generate only server certificate (CA must exist)"
    echo "  --client-only   Generate only client certificate (CA must exist)"
    echo "  --help          Show this help message"
    exit 0
fi

echo -e "${GREEN}====================================================================${NC}"
echo -e "${GREEN}  Génération de certificats TLS pour collectd tcpsock${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo ""

# Créer le répertoire
if [ ! -d "$TLS_DIR" ]; then
    echo -e "${YELLOW}Création du répertoire $TLS_DIR...${NC}"
    mkdir -p "$TLS_DIR"
fi

cd "$TLS_DIR"

# ==================================================================
# Fonction : Générer la CA
# ==================================================================
generate_ca() {
    echo -e "${GREEN}1. Génération de l'autorité de certification (CA)...${NC}"

    if [ -f "ca.key" ] && [ -f "ca.crt" ]; then
        echo -e "${YELLOW}   CA existe déjà. Utilisation de la CA existante.${NC}"
        return
    fi

    # Générer la clé privée CA (sans mot de passe pour automatisation)
    echo -e "${GREEN}   Génération de la clé privée CA...${NC}"
    openssl genrsa -out ca.key 4096 2>/dev/null

    # Générer le certificat CA
    echo -e "${GREEN}   Génération du certificat CA (valide $CA_DAYS jours)...${NC}"
    openssl req -new -x509 -days "$CA_DAYS" -key ca.key -out ca.crt \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CA_CN" 2>/dev/null

    echo -e "${GREEN}   ✓ CA créée avec succès${NC}"
    echo -e "     - Clé privée: $TLS_DIR/ca.key"
    echo -e "     - Certificat: $TLS_DIR/ca.crt"
}

# ==================================================================
# Fonction : Générer le certificat serveur
# ==================================================================
generate_server() {
    echo -e "${GREEN}2. Génération du certificat serveur...${NC}"

    # Vérifier que la CA existe
    if [ ! -f "ca.key" ] || [ ! -f "ca.crt" ]; then
        echo -e "${RED}   ERREUR: CA non trouvée. Exécutez d'abord sans --server-only${NC}"
        exit 1
    fi

    # Générer la clé privée du serveur
    echo -e "${GREEN}   Génération de la clé privée serveur...${NC}"
    openssl genrsa -out server.key 2048 2>/dev/null

    # Créer une demande de signature (CSR)
    echo -e "${GREEN}   Génération de la CSR...${NC}"
    openssl req -new -key server.key -out server.csr \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$SERVER_CN" 2>/dev/null

    # Signer le certificat avec la CA
    echo -e "${GREEN}   Signature du certificat serveur (valide $CERT_DAYS jours)...${NC}"
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out server.crt -days "$CERT_DAYS" 2>/dev/null

    # Supprimer la CSR (plus nécessaire)
    rm -f server.csr

    echo -e "${GREEN}   ✓ Certificat serveur créé avec succès${NC}"
    echo -e "     - Clé privée: $TLS_DIR/server.key"
    echo -e "     - Certificat: $TLS_DIR/server.crt"
}

# ==================================================================
# Fonction : Générer le certificat client
# ==================================================================
generate_client() {
    echo -e "${GREEN}3. Génération du certificat client...${NC}"

    # Vérifier que la CA existe
    if [ ! -f "ca.key" ] || [ ! -f "ca.crt" ]; then
        echo -e "${RED}   ERREUR: CA non trouvée. Exécutez d'abord sans --client-only${NC}"
        exit 1
    fi

    # Générer la clé privée du client
    echo -e "${GREEN}   Génération de la clé privée client...${NC}"
    openssl genrsa -out client.key 2048 2>/dev/null

    # Créer une demande de signature (CSR)
    echo -e "${GREEN}   Génération de la CSR...${NC}"
    openssl req -new -key client.key -out client.csr \
        -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG/CN=$CLIENT_CN" 2>/dev/null

    # Signer le certificat avec la CA
    echo -e "${GREEN}   Signature du certificat client (valide $CERT_DAYS jours)...${NC}"
    openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
        -CAcreateserial -out client.crt -days "$CERT_DAYS" 2>/dev/null

    # Supprimer la CSR
    rm -f client.csr

    echo -e "${GREEN}   ✓ Certificat client créé avec succès${NC}"
    echo -e "     - Clé privée: $TLS_DIR/client.key"
    echo -e "     - Certificat: $TLS_DIR/client.crt"
}

# ==================================================================
# Fonction : Définir les permissions
# ==================================================================
set_permissions() {
    echo -e "${GREEN}4. Configuration des permissions...${NC}"

    # Protéger les clés privées (lecture seule par le propriétaire)
    chmod 600 "$TLS_DIR"/*.key 2>/dev/null || true

    # Certificats publics (lecture pour tous)
    chmod 644 "$TLS_DIR"/*.crt 2>/dev/null || true

    # Propriétaire collectd (si l'utilisateur existe)
    if id collectd &>/dev/null; then
        chown -R collectd:collectd "$TLS_DIR"
        echo -e "${GREEN}   ✓ Propriétaire: collectd:collectd${NC}"
    else
        chown -R root:root "$TLS_DIR"
        echo -e "${YELLOW}   ⚠ Utilisateur collectd non trouvé, propriétaire: root:root${NC}"
    fi

    echo -e "${GREEN}   ✓ Permissions configurées${NC}"
}

# ==================================================================
# Fonction : Vérifier les certificats
# ==================================================================
verify_certs() {
    echo -e "${GREEN}5. Vérification des certificats...${NC}"

    # Vérifier le certificat serveur
    if [ -f "server.crt" ]; then
        if openssl verify -CAfile ca.crt server.crt &>/dev/null; then
            echo -e "${GREEN}   ✓ Certificat serveur: VALIDE${NC}"
        else
            echo -e "${RED}   ✗ Certificat serveur: INVALIDE${NC}"
        fi
    fi

    # Vérifier le certificat client
    if [ -f "client.crt" ]; then
        if openssl verify -CAfile ca.crt client.crt &>/dev/null; then
            echo -e "${GREEN}   ✓ Certificat client: VALIDE${NC}"
        else
            echo -e "${RED}   ✗ Certificat client: INVALIDE${NC}"
        fi
    fi

    # Vérifier la correspondance clé/certificat serveur
    if [ -f "server.key" ] && [ -f "server.crt" ]; then
        SERVER_KEY_MD5=$(openssl rsa -noout -modulus -in server.key 2>/dev/null | openssl md5 | cut -d' ' -f2)
        SERVER_CRT_MD5=$(openssl x509 -noout -modulus -in server.crt 2>/dev/null | openssl md5 | cut -d' ' -f2)

        if [ "$SERVER_KEY_MD5" = "$SERVER_CRT_MD5" ]; then
            echo -e "${GREEN}   ✓ Correspondance clé/certificat serveur: OK${NC}"
        else
            echo -e "${RED}   ✗ Correspondance clé/certificat serveur: ERREUR${NC}"
        fi
    fi
}

# ==================================================================
# Fonction : Afficher le résumé
# ==================================================================
show_summary() {
    echo ""
    echo -e "${GREEN}====================================================================${NC}"
    echo -e "${GREEN}  Génération terminée avec succès !${NC}"
    echo -e "${GREEN}====================================================================${NC}"
    echo ""
    echo -e "${YELLOW}Fichiers créés dans $TLS_DIR:${NC}"
    ls -lh "$TLS_DIR"
    echo ""
    echo -e "${YELLOW}Configuration collectd.conf (mode TLS sans auth client):${NC}"
    echo ""
    cat <<'EOF'
<Plugin "tcpsock">
    Listen "0.0.0.0" "25827"
    TLS true
    TLSCertificateFile "/etc/collectd/tls/server.crt"
    TLSKeyFile "/etc/collectd/tls/server.key"
</Plugin>
EOF
    echo ""
    echo -e "${YELLOW}Configuration collectd.conf (mode TLS avec auth client):${NC}"
    echo ""
    cat <<'EOF'
<Plugin "tcpsock">
    Listen "0.0.0.0" "25827"
    TLS true
    TLSCertificateFile "/etc/collectd/tls/server.crt"
    TLSKeyFile "/etc/collectd/tls/server.key"
    TLSCAFile "/etc/collectd/tls/ca.crt"
</Plugin>
EOF
    echo ""
    echo -e "${YELLOW}Test de connexion (sans auth client):${NC}"
    echo '  echo "LISTVAL" | openssl s_client -connect localhost:25827 -quiet'
    echo ""
    echo -e "${YELLOW}Test de connexion (avec auth client):${NC}"
    cat <<'EOF'
  echo "LISTVAL" | openssl s_client \
      -connect localhost:25827 \
      -cert /etc/collectd/tls/client.crt \
      -key /etc/collectd/tls/client.key \
      -CAfile /etc/collectd/tls/ca.crt \
      -quiet
EOF
    echo ""
}

# ==================================================================
# Exécution principale
# ==================================================================

case "$MODE" in
    "full")
        generate_ca
        generate_server
        generate_client
        ;;
    "server")
        generate_server
        ;;
    "client")
        generate_client
        ;;
esac

set_permissions
verify_certs
show_summary

echo -e "${GREEN}Terminé !${NC}"
exit 0
