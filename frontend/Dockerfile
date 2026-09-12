ARG NODE_IMAGE=node:20-alpine
ARG NGINX_IMAGE=nginx:alpine
ARG NPM_REGISTRY=https://registry.npmmirror.com

FROM ${NODE_IMAGE} AS builder

WORKDIR /app

ARG NPM_REGISTRY
ARG VITE_API_BASE_URL=/api
ENV PNPM_STORE_DIR=/pnpm/store
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm config set registry "${NPM_REGISTRY}" \
    && npm install --global pnpm@10.33.0 \
    && pnpm config set registry "${NPM_REGISTRY}" \
    && pnpm config set store-dir "${PNPM_STORE_DIR}"

COPY package.json pnpm-lock.yaml ./
RUN --mount=type=cache,id=sprint-flow-demo-frontend-pnpm,target=/pnpm/store \
    pnpm install --frozen-lockfile --prefer-offline

COPY . .
RUN pnpm build

FROM ${NGINX_IMAGE}

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/templates/default.conf.template

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
