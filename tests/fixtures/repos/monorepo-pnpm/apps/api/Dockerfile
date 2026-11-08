FROM node:20.15-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
USER node
CMD ["node", "index.js"]
