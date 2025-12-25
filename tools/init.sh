#!/bin/bash

echo "Setting secrets..."
echo "your_strong_jwt_secret" | wrangler secret put JWT_SECRET
echo "your_strong_refresh_secret" | wrangler secret put JWT_REFRESH_SECRET

echo "Initializing database..."
wrangler d1 execute warden-db --remote --file=./schema.sql

echo "Deploying..."
wrangler deploy

echo "✅ Deployment complete!"