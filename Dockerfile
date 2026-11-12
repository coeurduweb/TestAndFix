FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
COPY server/package.json server/
COPY web/package.json web/
RUN npm ci
COPY . .
# The web bundle is built here unless web/dist is already present in the build context (Vite needs
# a CPU with AVX2: on an older server, build web/dist elsewhere and ship it with the sources).
RUN npm run build -w server && (test -f web/dist/index.html || npm run build -w web)

FROM node:22-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/server/package.json server/
COPY --from=build /app/web/package.json web/
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/server/dist server/dist
COPY --from=build /app/server/data-seed server/data-seed
COPY --from=build /app/web/dist web/dist
COPY --from=build /app/knowledge knowledge
COPY --from=build /app/i18n i18n
COPY --from=build /app/research/dnsbl.json research/dnsbl.json
EXPOSE 3000 25
WORKDIR /app/server
CMD ["node", "dist/index.js"]
