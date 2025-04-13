#!/bin/bash

STATUS="$(curl --no-progress-meter --write-out '%{http_code}\n' --output hook-response.txt --insecure "${DEPLOY_HOOK}")"
echo "Webhook response status code: ${STATUS}"

if [[ "${STATUS}" -eq 200 ]]; then
	(
		echo "Successfully deployed to \`${BRANCH}\`. It is now at:"
		echo '```'
		git show --no-patch HEAD
		echo '```'
	) > message.txt

	curl \
		--no-progress-meter \
		--output /dev/null \
		--form-string 'avatar_url=https://emoji.gg/assets/emoji/PandaHugg.png' \
		--form "content=<message.txt" \
		"${DISCORD_HOOK}"
else
	curl \
		--no-progress-meter \
		--output /dev/null \
		--form-string 'avatar_url=https://emoji.gg/assets/emoji/PandaAh.png' \
		--form-string "content=Deploy to \`${BRANCH}\` **failed!**" \
		--form 'file=@hook-response.txt' \
		"${DISCORD_HOOK}"
fi
