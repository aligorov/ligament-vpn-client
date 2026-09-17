#!/bin/bash
# Enable-LigamentVPN.command — первый запуск Ligament VPN на macOS.
#
# Сборка не имеет подписи Apple Developer ID, поэтому macOS (Gatekeeper)
# помечает скачанное приложение карантином и на Apple Silicon пишет
# «приложение повреждено». Двойной клик по этому файлу снимает карантин
# и запускает приложение. Повторно не нужен.

set -u

APP="/Applications/Ligament VPN.app"

if [ ! -d "$APP" ]; then
  echo "❌ Не найдено: $APP"
  echo "   Сначала перетащите Ligament VPN из образа DMG в «Программы»."
  read -r -p "Нажмите Enter для закрытия…" _
  exit 1
fi

echo "Снимаю карантин Gatekeeper с $APP …"
xattr -cr "$APP"

echo "Запускаю Ligament VPN…"
open "$APP"

echo "✅ Готово. Если система спросит подтверждение — нажмите «Открыть»."
read -r -p "Нажмите Enter для закрытия…" _
