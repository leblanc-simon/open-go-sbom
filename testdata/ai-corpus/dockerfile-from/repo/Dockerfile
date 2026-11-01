# Construction
FROM node:20.11.1-alpine3.19 AS build
WORKDIR /src
COPY . .
RUN npm ci && npm run build

FROM nginx:1.25.4-alpine
COPY --from=build /src/dist /usr/share/nginx/html
