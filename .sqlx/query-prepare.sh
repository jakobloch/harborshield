#!/bin/bash
# Prepare sqlx offline data

# Create target directory
mkdir -p target/sqlx

# Create database
export DATABASE_URL="sqlite:target/sqlx/db.sqlite?mode=rwc"

# Run migrations
sqlx database create
sqlx migrate run

# Prepare queries
cargo sqlx prepare