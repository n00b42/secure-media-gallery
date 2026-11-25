#!/bin/bash
# Deployment script for Secure Media Gallery with Poetry

set -e
cd "$(dirname "$0")"   # work from the project root, wherever the script is called from

echo "🚀 Secure Media Gallery Deployment with Poetry"
echo "=============================================="

# Check if Poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "📦 Installing Poetry..."
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
fi

echo "✓ Poetry installed"

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $python_version"

# Install dependencies
echo "📚 Installing dependencies..."
poetry install

# Create .env from the template on the first run (readable only by you: it holds the secret key)
if [ ! -f ".env" ]; then
    (umask 077 && cp .env.example .env)
    echo "📝 Created .env from .env.example"
fi

# Generate SECRET_KEY if it is missing or empty. An existing key is never
# replaced: changing it would invalidate every login session.
if ! grep -qE '^SECRET_KEY=.+' .env; then
    secret_key=$(python3 -c "import secrets; print(secrets.token_hex(32))")
    if grep -qE '^SECRET_KEY=' .env; then
        sed -i "s/^SECRET_KEY=.*/SECRET_KEY=${secret_key}/" .env   # hex only: safe in sed
    else
        printf '\nSECRET_KEY=%s\n' "$secret_key" >> .env
    fi
    chmod 600 .env
    echo "🔑 Generated a new SECRET_KEY in .env"
else
    echo "✓ SECRET_KEY already set in .env (left unchanged)"
fi

# Initialize database
echo "🗄️  Initializing database..."
poetry run python src/manage.py init-db

echo ""
echo "✅ Deployment complete!"
echo ""
echo "Create an invite key for the first account:"
echo "  poetry run python src/manage.py create-invite"
echo ""
echo "Start the application:"
echo "  poetry run python -m src.app                                   (development)"
echo "  poetry run gunicorn --worker-class gthread --workers 2 --threads 4 \\"
echo "      --timeout 60 --bind 127.0.0.1:5000 src.app:app             (production)"
echo ""
echo "Application will be available at http://localhost:5000"
echo ""
