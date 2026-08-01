# The public read-only demo — https://demo.exactsurface.com
#
# NOT part of the product. This is one of the three things the vendor hosts (marketing
# site, this demo, control plane); customers run the real product themselves.
#
# It is the **real frontend** with exactly one file replaced: `lib/transport.ts`, the
# module every API call goes through. The demo version serves static fixtures instead
# of making HTTP requests. Consequences:
#
#   * no backend, no database, no API — there is nothing to attack and no data
#     belonging to anyone. Read-only is not enforced, it is *structural*: there is
#     nowhere for a write to go.
#   * no duplicated UI. Every page, component and type is the product's own, so the
#     demo cannot drift into showing something we no longer ship.
#
# The swap happens here, during the image build, so `demo/` never appears in the
# product image and the repo holds no second copy of the frontend.
#
# Build:  docker build -f demo/Dockerfile -t exactsurface-demo .
# Run:    docker run -p 3000:3000 exactsurface-demo

FROM node:20-alpine AS build
WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./

# The one-file swap. Everything above this line is the product; everything the demo
# changes is this.
COPY demo/lib/fixtures.ts ./lib/fixtures.ts
COPY demo/lib/transport.ts ./lib/transport.ts

# No API to proxy to — the rewrite target is never used, but Next bakes it at build
# time, so give it something inert rather than leaving it pointing at a service that
# does not exist in this deployment.
ENV API_PROXY_TARGET=http://127.0.0.1:9

RUN npm run build \
    && grep -rq "demo.exactsurface.com" .next \
    && echo "demo fixtures are present in the build"

FROM node:20-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json /app/package-lock.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/.next ./.next
COPY --from=build /app/public ./public
COPY --from=build /app/next.config.mjs ./
EXPOSE 3000
CMD ["npm", "run", "start"]
