#!/bin/sh
set -a && source ~/.secrets/.env && set +a
DIR="$HOME/Desktop/sam_opps"
mkdir -p "$DIR"
DONE=0
TOTAL=$(wc -l < /tmp/sam_unique_urls.txt)
while IFS= read -r url; do
  DONE=$((DONE + 1))
  slug=$(echo "$url" | sed 's|https://sam.gov/opp/||;s|/view||')
  if [ -f "$DIR/${slug}.png" ]; then
    echo "[$DONE/$TOTAL] skip (cached): $slug"
    continue
  fi
  echo "[$DONE/$TOTAL] browsing: $slug"
  cargo run --features browser -- browse "$url" --wait 6 --out "$DIR" > "$DIR/${slug}.txt" 2>&1
done < /tmp/sam_unique_urls.txt
echo "DONE: $DONE opportunities scraped to $DIR"
