set -euo pipefail
VERSION="${1:-}"
MAIN_PY="main.py"

if [ ! -f "$MAIN_PY" ]; then
  echo -e "\e[31mНе найден $MAIN_PY — нужен main.py.\e[0m"
  exit 1
fi

echo -e "\e[34m== 1. Пуш кода в репозиторий (без .env — он в .gitignore) ==\e[0m"
git add -A
git commit -m "Release $VERSION" || echo "(нечего коммитить, идём дальше)"
git push origin main
echo -e "\e[34m== 2. Тег версии ==\e[0m"
git tag "$VERSION"
git push origin "$VERSION"

echo -e "\e[34m== 3. GitHub Release: инсталлятор как единственный asset ==\e[0m"
gh release create "$VERSION" "$MAIN_PY" \
  --title "$VERSION" \

echo -e "\e[32mГотово: код запушен в main, тег $VERSION создан, релиз опубликован.\e[0m"